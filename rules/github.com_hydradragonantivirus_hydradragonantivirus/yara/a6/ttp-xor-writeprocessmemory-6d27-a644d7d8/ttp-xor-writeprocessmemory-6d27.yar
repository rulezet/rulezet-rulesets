rule TTP_XOR_WriteProcessMemory_6d27 {
  strings:
    $key_6d27 = { 3a 55 [2] 08 77 [2] 0e 42 [2] 20 42 [2] 1f 5e }

  condition:
    any of them
}