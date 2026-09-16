rule TTP_XOR_WriteProcessMemory_bbf1 {
  strings:
    $key_bbf1 = { ec 83 [2] de a1 [2] d8 94 [2] f6 94 [2] c9 88 }

  condition:
    any of them
}