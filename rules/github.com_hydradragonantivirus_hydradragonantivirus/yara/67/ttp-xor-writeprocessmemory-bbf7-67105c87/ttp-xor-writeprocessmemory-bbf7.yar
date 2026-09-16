rule TTP_XOR_WriteProcessMemory_bbf7 {
  strings:
    $key_bbf7 = { ec 85 [2] de a7 [2] d8 92 [2] f6 92 [2] c9 8e }

  condition:
    any of them
}