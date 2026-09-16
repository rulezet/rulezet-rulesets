rule TTP_XOR_WriteProcessMemory_284e {
  strings:
    $key_284e = { 7f 3c [2] 4d 1e [2] 4b 2b [2] 65 2b [2] 5a 37 }

  condition:
    any of them
}