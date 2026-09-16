rule TTP_XOR_WriteProcessMemory_452c {
  strings:
    $key_452c = { 12 5e [2] 20 7c [2] 26 49 [2] 08 49 [2] 37 55 }

  condition:
    any of them
}