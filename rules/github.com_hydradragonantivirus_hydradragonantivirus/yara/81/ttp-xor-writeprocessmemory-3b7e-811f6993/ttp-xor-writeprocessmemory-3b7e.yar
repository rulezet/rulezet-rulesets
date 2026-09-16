rule TTP_XOR_WriteProcessMemory_3b7e {
  strings:
    $key_3b7e = { 6c 0c [2] 5e 2e [2] 58 1b [2] 76 1b [2] 49 07 }

  condition:
    any of them
}