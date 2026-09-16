rule TTP_XOR_WriteProcessMemory_423c {
  strings:
    $key_423c = { 15 4e [2] 27 6c [2] 21 59 [2] 0f 59 [2] 30 45 }

  condition:
    any of them
}