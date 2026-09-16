rule TTP_XOR_WriteProcessMemory_d52b {
  strings:
    $key_d52b = { 82 59 [2] b0 7b [2] b6 4e [2] 98 4e [2] a7 52 }

  condition:
    any of them
}