rule TTP_XOR_WriteProcessMemory_345c {
  strings:
    $key_345c = { 63 2e [2] 51 0c [2] 57 39 [2] 79 39 [2] 46 25 }

  condition:
    any of them
}