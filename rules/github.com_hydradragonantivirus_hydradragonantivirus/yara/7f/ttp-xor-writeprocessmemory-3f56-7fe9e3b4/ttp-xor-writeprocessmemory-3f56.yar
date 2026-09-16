rule TTP_XOR_WriteProcessMemory_3f56 {
  strings:
    $key_3f56 = { 68 24 [2] 5a 06 [2] 5c 33 [2] 72 33 [2] 4d 2f }

  condition:
    any of them
}