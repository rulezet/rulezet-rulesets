rule TTP_XOR_WriteProcessMemory_e65c {
  strings:
    $key_e65c = { b1 2e [2] 83 0c [2] 85 39 [2] ab 39 [2] 94 25 }

  condition:
    any of them
}