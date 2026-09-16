rule TTP_XOR_WriteProcessMemory_b205 {
  strings:
    $key_b205 = { e5 77 [2] d7 55 [2] d1 60 [2] ff 60 [2] c0 7c }

  condition:
    any of them
}