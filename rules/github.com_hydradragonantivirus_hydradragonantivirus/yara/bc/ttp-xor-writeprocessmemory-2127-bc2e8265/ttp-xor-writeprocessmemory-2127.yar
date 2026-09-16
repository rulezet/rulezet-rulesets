rule TTP_XOR_WriteProcessMemory_2127 {
  strings:
    $key_2127 = { 76 55 [2] 44 77 [2] 42 42 [2] 6c 42 [2] 53 5e }

  condition:
    any of them
}