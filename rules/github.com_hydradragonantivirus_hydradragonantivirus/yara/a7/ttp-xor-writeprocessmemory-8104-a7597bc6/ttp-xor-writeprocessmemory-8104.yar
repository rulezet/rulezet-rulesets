rule TTP_XOR_WriteProcessMemory_8104 {
  strings:
    $key_8104 = { d6 76 [2] e4 54 [2] e2 61 [2] cc 61 [2] f3 7d }

  condition:
    any of them
}