rule TTP_XOR_WriteProcessMemory_9aa2 {
  strings:
    $key_9aa2 = { cd d0 [2] ff f2 [2] f9 c7 [2] d7 c7 [2] e8 db }

  condition:
    any of them
}