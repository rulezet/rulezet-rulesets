rule TTP_XOR_WriteProcessMemory_0d5c {
  strings:
    $key_0d5c = { 5a 2e [2] 68 0c [2] 6e 39 [2] 40 39 [2] 7f 25 }

  condition:
    any of them
}