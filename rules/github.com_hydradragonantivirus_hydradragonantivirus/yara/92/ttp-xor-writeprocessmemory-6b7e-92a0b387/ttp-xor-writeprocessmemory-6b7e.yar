rule TTP_XOR_WriteProcessMemory_6b7e {
  strings:
    $key_6b7e = { 3c 0c [2] 0e 2e [2] 08 1b [2] 26 1b [2] 19 07 }

  condition:
    any of them
}