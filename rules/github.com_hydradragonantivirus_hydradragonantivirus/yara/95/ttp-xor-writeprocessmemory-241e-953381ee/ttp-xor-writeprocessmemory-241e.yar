rule TTP_XOR_WriteProcessMemory_241e {
  strings:
    $key_241e = { 73 6c [2] 41 4e [2] 47 7b [2] 69 7b [2] 56 67 }

  condition:
    any of them
}