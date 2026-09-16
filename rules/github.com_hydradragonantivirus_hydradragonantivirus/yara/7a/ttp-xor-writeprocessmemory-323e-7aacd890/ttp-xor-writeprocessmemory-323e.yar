rule TTP_XOR_WriteProcessMemory_323e {
  strings:
    $key_323e = { 65 4c [2] 57 6e [2] 51 5b [2] 7f 5b [2] 40 47 }

  condition:
    any of them
}