rule TTP_XOR_WriteProcessMemory_452d {
  strings:
    $key_452d = { 12 5f [2] 20 7d [2] 26 48 [2] 08 48 [2] 37 54 }

  condition:
    any of them
}