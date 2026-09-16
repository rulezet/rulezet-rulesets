rule TTP_XOR_WriteProcessMemory_247c {
  strings:
    $key_247c = { 73 0e [2] 41 2c [2] 47 19 [2] 69 19 [2] 56 05 }

  condition:
    any of them
}