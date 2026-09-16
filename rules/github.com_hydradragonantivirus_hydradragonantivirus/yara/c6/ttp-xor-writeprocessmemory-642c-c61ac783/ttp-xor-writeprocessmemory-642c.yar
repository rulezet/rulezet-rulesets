rule TTP_XOR_WriteProcessMemory_642c {
  strings:
    $key_642c = { 33 5e [2] 01 7c [2] 07 49 [2] 29 49 [2] 16 55 }

  condition:
    any of them
}