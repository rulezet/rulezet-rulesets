rule TTP_XOR_WriteProcessMemory_381e {
  strings:
    $key_381e = { 6f 6c [2] 5d 4e [2] 5b 7b [2] 75 7b [2] 4a 67 }

  condition:
    any of them
}