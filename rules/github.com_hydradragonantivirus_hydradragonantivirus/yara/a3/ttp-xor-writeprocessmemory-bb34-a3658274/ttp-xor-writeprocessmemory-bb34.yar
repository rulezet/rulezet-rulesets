rule TTP_XOR_WriteProcessMemory_bb34 {
  strings:
    $key_bb34 = { ec 46 [2] de 64 [2] d8 51 [2] f6 51 [2] c9 4d }

  condition:
    any of them
}