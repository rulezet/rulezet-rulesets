rule TTP_XOR_WriteProcessMemory_fa4e {
  strings:
    $key_fa4e = { ad 3c [2] 9f 1e [2] 99 2b [2] b7 2b [2] 88 37 }

  condition:
    any of them
}