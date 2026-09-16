rule TTP_XOR_WriteProcessMemory_d51c {
  strings:
    $key_d51c = { 82 6e [2] b0 4c [2] b6 79 [2] 98 79 [2] a7 65 }

  condition:
    any of them
}