rule TTP_XOR_WriteProcessMemory_2d77 {
  strings:
    $key_2d77 = { 7a 05 [2] 48 27 [2] 4e 12 [2] 60 12 [2] 5f 0e }

  condition:
    any of them
}