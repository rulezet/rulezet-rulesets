rule TTP_XOR_WriteProcessMemory_c87c {
  strings:
    $key_c87c = { 9f 0e [2] ad 2c [2] ab 19 [2] 85 19 [2] ba 05 }

  condition:
    any of them
}