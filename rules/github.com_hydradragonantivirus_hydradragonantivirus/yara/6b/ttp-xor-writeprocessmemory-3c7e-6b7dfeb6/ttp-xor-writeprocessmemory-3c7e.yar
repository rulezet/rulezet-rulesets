rule TTP_XOR_WriteProcessMemory_3c7e {
  strings:
    $key_3c7e = { 6b 0c [2] 59 2e [2] 5f 1b [2] 71 1b [2] 4e 07 }

  condition:
    any of them
}