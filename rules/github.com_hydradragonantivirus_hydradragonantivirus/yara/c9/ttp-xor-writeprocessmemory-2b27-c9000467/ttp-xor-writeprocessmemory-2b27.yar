rule TTP_XOR_WriteProcessMemory_2b27 {
  strings:
    $key_2b27 = { 7c 55 [2] 4e 77 [2] 48 42 [2] 66 42 [2] 59 5e }

  condition:
    any of them
}