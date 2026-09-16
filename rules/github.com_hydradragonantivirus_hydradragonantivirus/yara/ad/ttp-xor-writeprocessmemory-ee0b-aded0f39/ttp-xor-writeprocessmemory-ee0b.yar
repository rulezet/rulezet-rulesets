rule TTP_XOR_WriteProcessMemory_ee0b {
  strings:
    $key_ee0b = { b9 79 [2] 8b 5b [2] 8d 6e [2] a3 6e [2] 9c 72 }

  condition:
    any of them
}