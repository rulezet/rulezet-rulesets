rule TTP_XOR_WriteProcessMemory_bbea {
  strings:
    $key_bbea = { ec 98 [2] de ba [2] d8 8f [2] f6 8f [2] c9 93 }

  condition:
    any of them
}