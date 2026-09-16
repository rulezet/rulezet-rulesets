rule TTP_XOR_WriteProcessMemory_fa1e {
  strings:
    $key_fa1e = { ad 6c [2] 9f 4e [2] 99 7b [2] b7 7b [2] 88 67 }

  condition:
    any of them
}