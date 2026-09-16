rule TTP_XOR_WriteProcessMemory_9aa4 {
  strings:
    $key_9aa4 = { cd d6 [2] ff f4 [2] f9 c1 [2] d7 c1 [2] e8 dd }

  condition:
    any of them
}