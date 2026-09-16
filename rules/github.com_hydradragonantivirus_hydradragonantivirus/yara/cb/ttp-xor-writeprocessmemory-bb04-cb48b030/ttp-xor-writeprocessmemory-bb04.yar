rule TTP_XOR_WriteProcessMemory_bb04 {
  strings:
    $key_bb04 = { ec 76 [2] de 54 [2] d8 61 [2] f6 61 [2] c9 7d }

  condition:
    any of them
}