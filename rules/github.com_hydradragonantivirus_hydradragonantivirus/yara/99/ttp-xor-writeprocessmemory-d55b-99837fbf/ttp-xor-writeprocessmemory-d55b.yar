rule TTP_XOR_WriteProcessMemory_d55b {
  strings:
    $key_d55b = { 82 29 [2] b0 0b [2] b6 3e [2] 98 3e [2] a7 22 }

  condition:
    any of them
}