rule TTP_XOR_WriteProcessMemory_311c {
  strings:
    $key_311c = { 66 6e [2] 54 4c [2] 52 79 [2] 7c 79 [2] 43 65 }

  condition:
    any of them
}