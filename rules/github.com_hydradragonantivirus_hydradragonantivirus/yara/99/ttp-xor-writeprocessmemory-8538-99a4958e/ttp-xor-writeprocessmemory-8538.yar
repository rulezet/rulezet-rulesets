rule TTP_XOR_WriteProcessMemory_8538 {
  strings:
    $key_8538 = { d2 4a [2] e0 68 [2] e6 5d [2] c8 5d [2] f7 41 }

  condition:
    any of them
}