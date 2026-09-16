rule TTP_XOR_WriteProcessMemory_adb2 {
  strings:
    $key_adb2 = { fa c0 [2] c8 e2 [2] ce d7 [2] e0 d7 [2] df cb }

  condition:
    any of them
}