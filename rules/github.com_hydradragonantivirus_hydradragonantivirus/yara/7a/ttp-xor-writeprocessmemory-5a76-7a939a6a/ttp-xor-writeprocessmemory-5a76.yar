rule TTP_XOR_WriteProcessMemory_5a76 {
  strings:
    $key_5a76 = { 0d 04 [2] 3f 26 [2] 39 13 [2] 17 13 [2] 28 0f }

  condition:
    any of them
}