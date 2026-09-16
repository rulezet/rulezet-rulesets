rule TTP_XOR_WriteProcessMemory_0927 {
  strings:
    $key_0927 = { 5e 55 [2] 6c 77 [2] 6a 42 [2] 44 42 [2] 7b 5e }

  condition:
    any of them
}