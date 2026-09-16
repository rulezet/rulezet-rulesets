rule TTP_XOR_WriteProcessMemory_bbe7 {
  strings:
    $key_bbe7 = { ec 95 [2] de b7 [2] d8 82 [2] f6 82 [2] c9 9e }

  condition:
    any of them
}