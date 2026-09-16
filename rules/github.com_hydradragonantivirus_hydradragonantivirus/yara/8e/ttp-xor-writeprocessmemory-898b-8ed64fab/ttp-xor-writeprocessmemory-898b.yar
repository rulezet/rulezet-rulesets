rule TTP_XOR_WriteProcessMemory_898b {
  strings:
    $key_898b = { de f9 [2] ec db [2] ea ee [2] c4 ee [2] fb f2 }

  condition:
    any of them
}