rule TTP_XOR_WriteProcessMemory_b514 {
  strings:
    $key_b514 = { e2 66 [2] d0 44 [2] d6 71 [2] f8 71 [2] c7 6d }

  condition:
    any of them
}