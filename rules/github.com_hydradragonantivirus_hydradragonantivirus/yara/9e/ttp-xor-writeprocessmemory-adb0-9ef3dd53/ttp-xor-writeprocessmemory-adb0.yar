rule TTP_XOR_WriteProcessMemory_adb0 {
  strings:
    $key_adb0 = { fa c2 [2] c8 e0 [2] ce d5 [2] e0 d5 [2] df c9 }

  condition:
    any of them
}