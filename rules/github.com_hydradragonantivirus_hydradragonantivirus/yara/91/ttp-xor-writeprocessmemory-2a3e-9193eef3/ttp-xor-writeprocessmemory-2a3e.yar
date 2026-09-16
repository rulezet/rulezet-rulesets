rule TTP_XOR_WriteProcessMemory_2a3e {
  strings:
    $key_2a3e = { 7d 4c [2] 4f 6e [2] 49 5b [2] 67 5b [2] 58 47 }

  condition:
    any of them
}