rule TTP_XOR_WriteProcessMemory_c701 {
  strings:
    $key_c701 = { 90 73 [2] a2 51 [2] a4 64 [2] 8a 64 [2] b5 78 }

  condition:
    any of them
}