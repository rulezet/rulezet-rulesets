rule TTP_XOR_WriteProcessMemory_3aa4 {
  strings:
    $key_3aa4 = { 6d d6 [2] 5f f4 [2] 59 c1 [2] 77 c1 [2] 48 dd }

  condition:
    any of them
}