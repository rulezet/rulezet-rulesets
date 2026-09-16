rule TTP_XOR_WriteProcessMemory_3b3e {
  strings:
    $key_3b3e = { 6c 4c [2] 5e 6e [2] 58 5b [2] 76 5b [2] 49 47 }

  condition:
    any of them
}