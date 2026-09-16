rule TTP_XOR_WriteProcessMemory_757c {
  strings:
    $key_757c = { 22 0e [2] 10 2c [2] 16 19 [2] 38 19 [2] 07 05 }

  condition:
    any of them
}