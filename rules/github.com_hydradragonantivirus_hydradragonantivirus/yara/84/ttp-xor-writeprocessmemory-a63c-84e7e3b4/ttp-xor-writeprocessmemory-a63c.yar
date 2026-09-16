rule TTP_XOR_WriteProcessMemory_a63c {
  strings:
    $key_a63c = { f1 4e [2] c3 6c [2] c5 59 [2] eb 59 [2] d4 45 }

  condition:
    any of them
}