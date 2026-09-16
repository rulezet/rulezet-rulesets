rule TTP_XOR_WriteProcessMemory_a01b {
  strings:
    $key_a01b = { f7 69 [2] c5 4b [2] c3 7e [2] ed 7e [2] d2 62 }

  condition:
    any of them
}