rule TTP_XOR_WriteProcessMemory_b369 {
  strings:
    $key_b369 = { e4 1b [2] d6 39 [2] d0 0c [2] fe 0c [2] c1 10 }

  condition:
    any of them
}