rule TTP_XOR_WriteProcessMemory_0c7e {
  strings:
    $key_0c7e = { 5b 0c [2] 69 2e [2] 6f 1b [2] 41 1b [2] 7e 07 }

  condition:
    any of them
}