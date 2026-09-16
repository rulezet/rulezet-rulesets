rule TTP_XOR_WriteProcessMemory_dafb {
  strings:
    $key_dafb = { 8d 89 [2] bf ab [2] b9 9e [2] 97 9e [2] a8 82 }

  condition:
    any of them
}