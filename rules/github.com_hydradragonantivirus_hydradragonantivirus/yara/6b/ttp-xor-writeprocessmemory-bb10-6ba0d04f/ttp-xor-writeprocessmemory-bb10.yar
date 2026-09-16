rule TTP_XOR_WriteProcessMemory_bb10 {
  strings:
    $key_bb10 = { ec 62 [2] de 40 [2] d8 75 [2] f6 75 [2] c9 69 }

  condition:
    any of them
}