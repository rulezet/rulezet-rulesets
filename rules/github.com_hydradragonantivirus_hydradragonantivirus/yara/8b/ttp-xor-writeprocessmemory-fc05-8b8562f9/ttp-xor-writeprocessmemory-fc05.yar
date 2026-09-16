rule TTP_XOR_WriteProcessMemory_fc05 {
  strings:
    $key_fc05 = { ab 77 [2] 99 55 [2] 9f 60 [2] b1 60 [2] 8e 7c }

  condition:
    any of them
}