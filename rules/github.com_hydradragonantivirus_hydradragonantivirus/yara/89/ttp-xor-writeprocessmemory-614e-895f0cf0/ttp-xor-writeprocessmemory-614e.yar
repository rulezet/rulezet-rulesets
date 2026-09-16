rule TTP_XOR_WriteProcessMemory_614e {
  strings:
    $key_614e = { 36 3c [2] 04 1e [2] 02 2b [2] 2c 2b [2] 13 37 }

  condition:
    any of them
}