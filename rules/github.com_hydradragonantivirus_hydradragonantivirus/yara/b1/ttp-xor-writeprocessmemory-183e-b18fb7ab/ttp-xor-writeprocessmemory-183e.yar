rule TTP_XOR_WriteProcessMemory_183e {
  strings:
    $key_183e = { 4f 4c [2] 7d 6e [2] 7b 5b [2] 55 5b [2] 6a 47 }

  condition:
    any of them
}