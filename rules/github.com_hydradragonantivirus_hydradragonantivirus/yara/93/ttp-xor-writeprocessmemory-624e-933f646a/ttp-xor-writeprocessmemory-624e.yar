rule TTP_XOR_WriteProcessMemory_624e {
  strings:
    $key_624e = { 35 3c [2] 07 1e [2] 01 2b [2] 2f 2b [2] 10 37 }

  condition:
    any of them
}