rule TTP_XOR_WriteProcessMemory_227e {
  strings:
    $key_227e = { 75 0c [2] 47 2e [2] 41 1b [2] 6f 1b [2] 50 07 }

  condition:
    any of them
}