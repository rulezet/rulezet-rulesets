rule TTP_XOR_WriteProcessMemory_e946 {
  strings:
    $key_e946 = { be 34 [2] 8c 16 [2] 8a 23 [2] a4 23 [2] 9b 3f }

  condition:
    any of them
}