rule TTP_XOR_WriteProcessMemory_4c7e {
  strings:
    $key_4c7e = { 1b 0c [2] 29 2e [2] 2f 1b [2] 01 1b [2] 3e 07 }

  condition:
    any of them
}