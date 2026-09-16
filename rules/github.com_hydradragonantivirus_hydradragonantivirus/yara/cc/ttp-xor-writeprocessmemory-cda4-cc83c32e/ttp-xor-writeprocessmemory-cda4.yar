rule TTP_XOR_WriteProcessMemory_cda4 {
  strings:
    $key_cda4 = { 9a d6 [2] a8 f4 [2] ae c1 [2] 80 c1 [2] bf dd }

  condition:
    any of them
}