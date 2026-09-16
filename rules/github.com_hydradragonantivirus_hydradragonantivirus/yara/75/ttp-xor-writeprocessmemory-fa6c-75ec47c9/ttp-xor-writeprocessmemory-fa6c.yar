rule TTP_XOR_WriteProcessMemory_fa6c {
  strings:
    $key_fa6c = { ad 1e [2] 9f 3c [2] 99 09 [2] b7 09 [2] 88 15 }

  condition:
    any of them
}