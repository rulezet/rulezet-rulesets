rule TTP_XOR_WriteProcessMemory_4b27 {
  strings:
    $key_4b27 = { 1c 55 [2] 2e 77 [2] 28 42 [2] 06 42 [2] 39 5e }

  condition:
    any of them
}