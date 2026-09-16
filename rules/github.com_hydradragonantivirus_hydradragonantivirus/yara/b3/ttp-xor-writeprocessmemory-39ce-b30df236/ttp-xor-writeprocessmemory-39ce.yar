rule TTP_XOR_WriteProcessMemory_39ce {
  strings:
    $key_39ce = { 6e bc [2] 5c 9e [2] 5a ab [2] 74 ab [2] 4b b7 }

  condition:
    any of them
}