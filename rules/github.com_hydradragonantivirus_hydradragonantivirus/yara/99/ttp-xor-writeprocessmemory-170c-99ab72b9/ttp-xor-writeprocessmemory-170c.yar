rule TTP_XOR_WriteProcessMemory_170c {
  strings:
    $key_170c = { 40 7e [2] 72 5c [2] 74 69 [2] 5a 69 [2] 65 75 }

  condition:
    any of them
}