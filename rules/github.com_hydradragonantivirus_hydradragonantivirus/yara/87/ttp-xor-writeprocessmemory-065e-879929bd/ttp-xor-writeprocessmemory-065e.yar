rule TTP_XOR_WriteProcessMemory_065e {
  strings:
    $key_065e = { 51 2c [2] 63 0e [2] 65 3b [2] 4b 3b [2] 74 27 }

  condition:
    any of them
}