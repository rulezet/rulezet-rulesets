rule TTP_XOR_WriteProcessMemory_2a7e {
  strings:
    $key_2a7e = { 7d 0c [2] 4f 2e [2] 49 1b [2] 67 1b [2] 58 07 }

  condition:
    any of them
}