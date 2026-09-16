rule TTP_XOR_WriteProcessMemory_3aa1 {
  strings:
    $key_3aa1 = { 6d d3 [2] 5f f1 [2] 59 c4 [2] 77 c4 [2] 48 d8 }

  condition:
    any of them
}