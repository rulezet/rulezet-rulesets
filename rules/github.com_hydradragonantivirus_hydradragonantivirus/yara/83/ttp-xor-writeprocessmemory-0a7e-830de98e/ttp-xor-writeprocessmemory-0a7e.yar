rule TTP_XOR_WriteProcessMemory_0a7e {
  strings:
    $key_0a7e = { 5d 0c [2] 6f 2e [2] 69 1b [2] 47 1b [2] 78 07 }

  condition:
    any of them
}