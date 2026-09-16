rule TTP_XOR_WriteProcessMemory_d52c {
  strings:
    $key_d52c = { 82 5e [2] b0 7c [2] b6 49 [2] 98 49 [2] a7 55 }

  condition:
    any of them
}