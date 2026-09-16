rule TTP_XOR_WriteProcessMemory_bb8d {
  strings:
    $key_bb8d = { ec ff [2] de dd [2] d8 e8 [2] f6 e8 [2] c9 f4 }

  condition:
    any of them
}