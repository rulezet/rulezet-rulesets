rule TTP_XOR_WriteProcessMemory_8137 {
  strings:
    $key_8137 = { d6 45 [2] e4 67 [2] e2 52 [2] cc 52 [2] f3 4e }

  condition:
    any of them
}