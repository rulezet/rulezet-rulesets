rule TTP_XOR_WriteProcessMemory_fa2e {
  strings:
    $key_fa2e = { ad 5c [2] 9f 7e [2] 99 4b [2] b7 4b [2] 88 57 }

  condition:
    any of them
}