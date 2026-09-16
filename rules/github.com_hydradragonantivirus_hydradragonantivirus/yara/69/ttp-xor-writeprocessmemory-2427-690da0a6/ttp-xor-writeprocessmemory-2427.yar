rule TTP_XOR_WriteProcessMemory_2427 {
  strings:
    $key_2427 = { 73 55 [2] 41 77 [2] 47 42 [2] 69 42 [2] 56 5e }

  condition:
    any of them
}