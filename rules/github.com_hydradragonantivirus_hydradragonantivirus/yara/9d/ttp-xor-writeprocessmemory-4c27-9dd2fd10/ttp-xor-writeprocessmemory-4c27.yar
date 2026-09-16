rule TTP_XOR_WriteProcessMemory_4c27 {
  strings:
    $key_4c27 = { 1b 55 [2] 29 77 [2] 2f 42 [2] 01 42 [2] 3e 5e }

  condition:
    any of them
}