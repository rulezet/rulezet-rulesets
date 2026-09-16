rule TTP_XOR_WriteProcessMemory_8723 {
  strings:
    $key_8723 = { d0 51 [2] e2 73 [2] e4 46 [2] ca 46 [2] f5 5a }

  condition:
    any of them
}