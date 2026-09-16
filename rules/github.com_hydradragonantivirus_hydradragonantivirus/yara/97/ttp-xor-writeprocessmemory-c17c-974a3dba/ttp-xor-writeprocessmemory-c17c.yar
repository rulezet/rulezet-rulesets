rule TTP_XOR_WriteProcessMemory_c17c {
  strings:
    $key_c17c = { 96 0e [2] a4 2c [2] a2 19 [2] 8c 19 [2] b3 05 }

  condition:
    any of them
}