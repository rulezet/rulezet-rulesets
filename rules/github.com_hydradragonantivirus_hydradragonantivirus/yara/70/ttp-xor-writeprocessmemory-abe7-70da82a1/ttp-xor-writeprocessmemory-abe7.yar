rule TTP_XOR_WriteProcessMemory_abe7 {
  strings:
    $key_abe7 = { fc 95 [2] ce b7 [2] c8 82 [2] e6 82 [2] d9 9e }

  condition:
    any of them
}