rule TTP_XOR_WriteProcessMemory_0d27 {
  strings:
    $key_0d27 = { 5a 55 [2] 68 77 [2] 6e 42 [2] 40 42 [2] 7f 5e }

  condition:
    any of them
}