rule TTP_XOR_WriteProcessMemory_c0f3 {
  strings:
    $key_c0f3 = { 97 81 [2] a5 a3 [2] a3 96 [2] 8d 96 [2] b2 8a }

  condition:
    any of them
}