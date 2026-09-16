rule TTP_XOR_WriteProcessMemory_1b27 {
  strings:
    $key_1b27 = { 4c 55 [2] 7e 77 [2] 78 42 [2] 56 42 [2] 69 5e }

  condition:
    any of them
}