rule TTP_XOR_WriteProcessMemory_0d12 {
  strings:
    $key_0d12 = { 5a 60 [2] 68 42 [2] 6e 77 [2] 40 77 [2] 7f 6b }

  condition:
    any of them
}