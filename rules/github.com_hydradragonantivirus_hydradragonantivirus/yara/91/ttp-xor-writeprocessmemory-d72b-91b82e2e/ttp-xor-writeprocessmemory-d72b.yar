rule TTP_XOR_WriteProcessMemory_d72b {
  strings:
    $key_d72b = { 80 59 [2] b2 7b [2] b4 4e [2] 9a 4e [2] a5 52 }

  condition:
    any of them
}