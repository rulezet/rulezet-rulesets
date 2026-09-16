rule TTP_XOR_WriteProcessMemory_fa69 {
  strings:
    $key_fa69 = { ad 1b [2] 9f 39 [2] 99 0c [2] b7 0c [2] 88 10 }

  condition:
    any of them
}