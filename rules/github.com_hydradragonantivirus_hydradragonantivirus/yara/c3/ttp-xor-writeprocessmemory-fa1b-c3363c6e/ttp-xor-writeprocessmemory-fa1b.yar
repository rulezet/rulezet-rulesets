rule TTP_XOR_WriteProcessMemory_fa1b {
  strings:
    $key_fa1b = { ad 69 [2] 9f 4b [2] 99 7e [2] b7 7e [2] 88 62 }

  condition:
    any of them
}