rule TTP_XOR_WriteProcessMemory_ac8b {
  strings:
    $key_ac8b = { fb f9 [2] c9 db [2] cf ee [2] e1 ee [2] de f2 }

  condition:
    any of them
}