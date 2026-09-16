rule TTP_XOR_WriteProcessMemory_625e {
  strings:
    $key_625e = { 35 2c [2] 07 0e [2] 01 3b [2] 2f 3b [2] 10 27 }

  condition:
    any of them
}