rule TTP_XOR_WriteProcessMemory_e925 {
  strings:
    $key_e925 = { be 57 [2] 8c 75 [2] 8a 40 [2] a4 40 [2] 9b 5c }

  condition:
    any of them
}