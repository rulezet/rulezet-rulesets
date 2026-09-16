rule TTP_XOR_WriteProcessMemory_8117 {
  strings:
    $key_8117 = { d6 65 [2] e4 47 [2] e2 72 [2] cc 72 [2] f3 6e }

  condition:
    any of them
}