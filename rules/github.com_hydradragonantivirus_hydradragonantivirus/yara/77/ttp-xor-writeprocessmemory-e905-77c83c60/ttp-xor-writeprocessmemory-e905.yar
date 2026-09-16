rule TTP_XOR_WriteProcessMemory_e905 {
  strings:
    $key_e905 = { be 77 [2] 8c 55 [2] 8a 60 [2] a4 60 [2] 9b 7c }

  condition:
    any of them
}