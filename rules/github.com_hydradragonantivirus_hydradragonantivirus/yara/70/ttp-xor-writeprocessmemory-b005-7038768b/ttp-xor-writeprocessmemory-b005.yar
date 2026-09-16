rule TTP_XOR_WriteProcessMemory_b005 {
  strings:
    $key_b005 = { e7 77 [2] d5 55 [2] d3 60 [2] fd 60 [2] c2 7c }

  condition:
    any of them
}