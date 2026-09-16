rule TTP_XOR_WriteProcessMemory_c703 {
  strings:
    $key_c703 = { 90 71 [2] a2 53 [2] a4 66 [2] 8a 66 [2] b5 7a }

  condition:
    any of them
}