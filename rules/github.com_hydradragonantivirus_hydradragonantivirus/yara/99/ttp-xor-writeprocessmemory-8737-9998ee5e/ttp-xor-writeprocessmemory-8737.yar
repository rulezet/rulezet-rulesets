rule TTP_XOR_WriteProcessMemory_8737 {
  strings:
    $key_8737 = { d0 45 [2] e2 67 [2] e4 52 [2] ca 52 [2] f5 4e }

  condition:
    any of them
}