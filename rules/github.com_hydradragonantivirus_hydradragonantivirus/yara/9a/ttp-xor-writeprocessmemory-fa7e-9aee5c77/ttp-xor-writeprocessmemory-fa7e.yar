rule TTP_XOR_WriteProcessMemory_fa7e {
  strings:
    $key_fa7e = { ad 0c [2] 9f 2e [2] 99 1b [2] b7 1b [2] 88 07 }

  condition:
    any of them
}