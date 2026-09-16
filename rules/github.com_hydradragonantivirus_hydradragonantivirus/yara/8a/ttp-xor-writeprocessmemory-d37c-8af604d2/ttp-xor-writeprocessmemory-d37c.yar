rule TTP_XOR_WriteProcessMemory_d37c {
  strings:
    $key_d37c = { 84 0e [2] b6 2c [2] b0 19 [2] 9e 19 [2] a1 05 }

  condition:
    any of them
}