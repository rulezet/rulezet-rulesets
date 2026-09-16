rule TTP_XOR_WriteProcessMemory_263e {
  strings:
    $key_263e = { 71 4c [2] 43 6e [2] 45 5b [2] 6b 5b [2] 54 47 }

  condition:
    any of them
}