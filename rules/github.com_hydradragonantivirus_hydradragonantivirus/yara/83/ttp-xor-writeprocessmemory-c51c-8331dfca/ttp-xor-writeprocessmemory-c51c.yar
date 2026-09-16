rule TTP_XOR_WriteProcessMemory_c51c {
  strings:
    $key_c51c = { 92 6e [2] a0 4c [2] a6 79 [2] 88 79 [2] b7 65 }

  condition:
    any of them
}