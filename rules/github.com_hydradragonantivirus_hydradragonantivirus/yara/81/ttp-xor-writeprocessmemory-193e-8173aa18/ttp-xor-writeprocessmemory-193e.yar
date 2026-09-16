rule TTP_XOR_WriteProcessMemory_193e {
  strings:
    $key_193e = { 4e 4c [2] 7c 6e [2] 7a 5b [2] 54 5b [2] 6b 47 }

  condition:
    any of them
}