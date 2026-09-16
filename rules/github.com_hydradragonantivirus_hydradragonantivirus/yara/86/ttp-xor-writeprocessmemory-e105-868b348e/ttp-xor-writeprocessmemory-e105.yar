rule TTP_XOR_WriteProcessMemory_e105 {
  strings:
    $key_e105 = { b6 77 [2] 84 55 [2] 82 60 [2] ac 60 [2] 93 7c }

  condition:
    any of them
}