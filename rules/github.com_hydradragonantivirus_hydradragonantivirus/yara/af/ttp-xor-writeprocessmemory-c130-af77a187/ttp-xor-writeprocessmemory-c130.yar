rule TTP_XOR_WriteProcessMemory_c130 {
  strings:
    $key_c130 = { 96 42 [2] a4 60 [2] a2 55 [2] 8c 55 [2] b3 49 }

  condition:
    any of them
}