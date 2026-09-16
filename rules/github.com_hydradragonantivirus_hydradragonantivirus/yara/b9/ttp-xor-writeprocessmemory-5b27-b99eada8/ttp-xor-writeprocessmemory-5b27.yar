rule TTP_XOR_WriteProcessMemory_5b27 {
  strings:
    $key_5b27 = { 0c 55 [2] 3e 77 [2] 38 42 [2] 16 42 [2] 29 5e }

  condition:
    any of them
}