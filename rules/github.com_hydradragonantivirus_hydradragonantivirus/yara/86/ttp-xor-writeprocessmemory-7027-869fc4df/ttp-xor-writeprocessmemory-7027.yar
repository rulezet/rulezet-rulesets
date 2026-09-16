rule TTP_XOR_WriteProcessMemory_7027 {
  strings:
    $key_7027 = { 27 55 [2] 15 77 [2] 13 42 [2] 3d 42 [2] 02 5e }

  condition:
    any of them
}