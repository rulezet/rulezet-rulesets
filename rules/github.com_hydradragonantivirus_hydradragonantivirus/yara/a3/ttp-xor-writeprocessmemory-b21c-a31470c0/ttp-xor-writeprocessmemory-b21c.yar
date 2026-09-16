rule TTP_XOR_WriteProcessMemory_b21c {
  strings:
    $key_b21c = { e5 6e [2] d7 4c [2] d1 79 [2] ff 79 [2] c0 65 }

  condition:
    any of them
}