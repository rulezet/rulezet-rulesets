rule TTP_XOR_WriteProcessMemory_8528 {
  strings:
    $key_8528 = { d2 5a [2] e0 78 [2] e6 4d [2] c8 4d [2] f7 51 }

  condition:
    any of them
}