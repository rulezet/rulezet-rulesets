rule TTP_XOR_WriteProcessMemory_c273 {
  strings:
    $key_c273 = { 95 01 [2] a7 23 [2] a1 16 [2] 8f 16 [2] b0 0a }

  condition:
    any of them
}