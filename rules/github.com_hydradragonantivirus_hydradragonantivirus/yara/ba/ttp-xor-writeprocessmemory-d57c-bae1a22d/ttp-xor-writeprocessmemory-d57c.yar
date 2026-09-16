rule TTP_XOR_WriteProcessMemory_d57c {
  strings:
    $key_d57c = { 82 0e [2] b0 2c [2] b6 19 [2] 98 19 [2] a7 05 }

  condition:
    any of them
}