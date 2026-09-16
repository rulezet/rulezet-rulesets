rule TTP_XOR_WriteProcessMemory_e964 {
  strings:
    $key_e964 = { be 16 [2] 8c 34 [2] 8a 01 [2] a4 01 [2] 9b 1d }

  condition:
    any of them
}