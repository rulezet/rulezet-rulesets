rule TTP_XOR_WriteProcessMemory_3c3e {
  strings:
    $key_3c3e = { 6b 4c [2] 59 6e [2] 5f 5b [2] 71 5b [2] 4e 47 }

  condition:
    any of them
}