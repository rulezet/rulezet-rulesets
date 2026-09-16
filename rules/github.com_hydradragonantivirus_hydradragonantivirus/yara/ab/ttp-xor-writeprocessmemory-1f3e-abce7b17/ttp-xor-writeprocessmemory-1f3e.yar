rule TTP_XOR_WriteProcessMemory_1f3e {
  strings:
    $key_1f3e = { 48 4c [2] 7a 6e [2] 7c 5b [2] 52 5b [2] 6d 47 }

  condition:
    any of them
}