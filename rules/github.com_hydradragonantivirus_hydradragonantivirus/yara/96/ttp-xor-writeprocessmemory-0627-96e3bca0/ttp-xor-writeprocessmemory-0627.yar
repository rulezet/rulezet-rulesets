rule TTP_XOR_WriteProcessMemory_0627 {
  strings:
    $key_0627 = { 51 55 [2] 63 77 [2] 65 42 [2] 4b 42 [2] 74 5e }

  condition:
    any of them
}