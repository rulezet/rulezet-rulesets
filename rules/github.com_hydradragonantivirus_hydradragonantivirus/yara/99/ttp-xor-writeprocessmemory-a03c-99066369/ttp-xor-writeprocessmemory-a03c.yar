rule TTP_XOR_WriteProcessMemory_a03c {
  strings:
    $key_a03c = { f7 4e [2] c5 6c [2] c3 59 [2] ed 59 [2] d2 45 }

  condition:
    any of them
}