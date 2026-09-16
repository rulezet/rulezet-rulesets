rule TTP_XOR_WriteProcessMemory_ed5c {
  strings:
    $key_ed5c = { ba 2e [2] 88 0c [2] 8e 39 [2] a0 39 [2] 9f 25 }

  condition:
    any of them
}