rule TTP_XOR_WriteProcessMemory_452e {
  strings:
    $key_452e = { 12 5c [2] 20 7e [2] 26 4b [2] 08 4b [2] 37 57 }

  condition:
    any of them
}