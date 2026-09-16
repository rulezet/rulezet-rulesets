rule TTP_XOR_WriteProcessMemory_063e {
  strings:
    $key_063e = { 51 4c [2] 63 6e [2] 65 5b [2] 4b 5b [2] 74 47 }

  condition:
    any of them
}