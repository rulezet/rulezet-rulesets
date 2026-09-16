rule TTP_XOR_WriteProcessMemory_bba2 {
  strings:
    $key_bba2 = { ec d0 [2] de f2 [2] d8 c7 [2] f6 c7 [2] c9 db }

  condition:
    any of them
}