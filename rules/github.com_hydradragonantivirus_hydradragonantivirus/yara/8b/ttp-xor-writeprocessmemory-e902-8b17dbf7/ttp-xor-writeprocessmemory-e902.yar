rule TTP_XOR_WriteProcessMemory_e902 {
  strings:
    $key_e902 = { be 70 [2] 8c 52 [2] 8a 67 [2] a4 67 [2] 9b 7b }

  condition:
    any of them
}