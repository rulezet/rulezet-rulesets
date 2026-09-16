rule TTP_XOR_WriteProcessMemory_175c {
  strings:
    $key_175c = { 40 2e [2] 72 0c [2] 74 39 [2] 5a 39 [2] 65 25 }

  condition:
    any of them
}