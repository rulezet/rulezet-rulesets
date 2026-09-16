rule TTP_XOR_WriteProcessMemory_7a27 {
  strings:
    $key_7a27 = { 2d 55 [2] 1f 77 [2] 19 42 [2] 37 42 [2] 08 5e }

  condition:
    any of them
}