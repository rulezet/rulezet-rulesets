rule TTP_XOR_WriteProcessMemory_6b27 {
  strings:
    $key_6b27 = { 3c 55 [2] 0e 77 [2] 08 42 [2] 26 42 [2] 19 5e }

  condition:
    any of them
}