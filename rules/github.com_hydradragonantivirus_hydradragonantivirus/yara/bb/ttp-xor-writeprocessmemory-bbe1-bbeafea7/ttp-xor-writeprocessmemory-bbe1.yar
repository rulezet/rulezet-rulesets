rule TTP_XOR_WriteProcessMemory_bbe1 {
  strings:
    $key_bbe1 = { ec 93 [2] de b1 [2] d8 84 [2] f6 84 [2] c9 98 }

  condition:
    any of them
}