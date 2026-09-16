rule TTP_XOR_WriteProcessMemory_f63c {
  strings:
    $key_f63c = { a1 4e [2] 93 6c [2] 95 59 [2] bb 59 [2] 84 45 }

  condition:
    any of them
}