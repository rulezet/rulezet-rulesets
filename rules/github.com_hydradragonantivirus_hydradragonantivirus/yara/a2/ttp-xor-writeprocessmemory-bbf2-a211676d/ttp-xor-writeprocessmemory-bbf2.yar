rule TTP_XOR_WriteProcessMemory_bbf2 {
  strings:
    $key_bbf2 = { ec 80 [2] de a2 [2] d8 97 [2] f6 97 [2] c9 8b }

  condition:
    any of them
}