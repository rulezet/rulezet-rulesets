rule TTP_XOR_WriteProcessMemory_521c {
  strings:
    $key_521c = { 05 6e [2] 37 4c [2] 31 79 [2] 1f 79 [2] 20 65 }

  condition:
    any of them
}