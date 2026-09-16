rule TTP_XOR_WriteProcessMemory_4826 {
  strings:
    $key_4826 = { 1f 54 [2] 2d 76 [2] 2b 43 [2] 05 43 [2] 3a 5f }

  condition:
    any of them
}