rule TTP_XOR_WriteProcessMemory_e966 {
  strings:
    $key_e966 = { be 14 [2] 8c 36 [2] 8a 03 [2] a4 03 [2] 9b 1f }

  condition:
    any of them
}