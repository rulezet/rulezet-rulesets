rule TTP_XOR_WriteProcessMemory_a50c {
  strings:
    $key_a50c = { f2 7e [2] c0 5c [2] c6 69 [2] e8 69 [2] d7 75 }

  condition:
    any of them
}