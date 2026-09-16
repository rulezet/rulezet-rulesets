rule TTP_XOR_WriteProcessMemory_c025 {
  strings:
    $key_c025 = { 97 57 [2] a5 75 [2] a3 40 [2] 8d 40 [2] b2 5c }

  condition:
    any of them
}