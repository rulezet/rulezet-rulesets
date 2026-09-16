rule TTP_XOR_WriteProcessMemory_bb8c {
  strings:
    $key_bb8c = { ec fe [2] de dc [2] d8 e9 [2] f6 e9 [2] c9 f5 }

  condition:
    any of them
}