rule TTP_XOR_WriteProcessMemory_aa93 {
  strings:
    $key_aa93 = { fd e1 [2] cf c3 [2] c9 f6 [2] e7 f6 [2] d8 ea }

  condition:
    any of them
}