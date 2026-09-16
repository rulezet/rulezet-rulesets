rule TTP_XOR_WriteProcessMemory_1c7e {
  strings:
    $key_1c7e = { 4b 0c [2] 79 2e [2] 7f 1b [2] 51 1b [2] 6e 07 }

  condition:
    any of them
}