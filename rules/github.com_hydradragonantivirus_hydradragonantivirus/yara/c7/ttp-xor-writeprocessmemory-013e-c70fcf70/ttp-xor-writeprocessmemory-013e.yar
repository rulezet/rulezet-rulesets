rule TTP_XOR_WriteProcessMemory_013e {
  strings:
    $key_013e = { 56 4c [2] 64 6e [2] 62 5b [2] 4c 5b [2] 73 47 }

  condition:
    any of them
}