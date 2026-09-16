rule TTP_XOR_WriteProcessMemory_e953 {
  strings:
    $key_e953 = { be 21 [2] 8c 03 [2] 8a 36 [2] a4 36 [2] 9b 2a }

  condition:
    any of them
}