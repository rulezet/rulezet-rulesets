rule TTP_XOR_WriteProcessMemory_c027 {
  strings:
    $key_c027 = { 97 55 [2] a5 77 [2] a3 42 [2] 8d 42 [2] b2 5e }

  condition:
    any of them
}