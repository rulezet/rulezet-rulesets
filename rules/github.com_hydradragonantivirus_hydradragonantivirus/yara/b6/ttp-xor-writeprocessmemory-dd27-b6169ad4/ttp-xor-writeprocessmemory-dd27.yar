rule TTP_XOR_WriteProcessMemory_dd27 {
  strings:
    $key_dd27 = { 8a 55 [2] b8 77 [2] be 42 [2] 90 42 [2] af 5e }

  condition:
    any of them
}