rule TTP_XOR_WriteProcessMemory_cc27 {
  strings:
    $key_cc27 = { 9b 55 [2] a9 77 [2] af 42 [2] 81 42 [2] be 5e }

  condition:
    any of them
}