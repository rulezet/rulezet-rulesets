rule TTP_XOR_WriteProcessMemory_fca4 {
  strings:
    $key_fca4 = { ab d6 [2] 99 f4 [2] 9f c1 [2] b1 c1 [2] 8e dd }

  condition:
    any of them
}