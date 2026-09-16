rule TTP_XOR_WriteProcessMemory_d54c {
  strings:
    $key_d54c = { 82 3e [2] b0 1c [2] b6 29 [2] 98 29 [2] a7 35 }

  condition:
    any of them
}