rule TTP_XOR_WriteProcessMemory_d04b {
  strings:
    $key_d04b = { 87 39 [2] b5 1b [2] b3 2e [2] 9d 2e [2] a2 32 }

  condition:
    any of them
}