rule TTP_XOR_WriteProcessMemory_0827 {
  strings:
    $key_0827 = { 5f 55 [2] 6d 77 [2] 6b 42 [2] 45 42 [2] 7a 5e }

  condition:
    any of them
}