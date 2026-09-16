rule TTP_XOR_WriteProcessMemory_192e {
  strings:
    $key_192e = { 4e 5c [2] 7c 7e [2] 7a 4b [2] 54 4b [2] 6b 57 }

  condition:
    any of them
}