rule TTP_XOR_WriteProcessMemory_8734 {
  strings:
    $key_8734 = { d0 46 [2] e2 64 [2] e4 51 [2] ca 51 [2] f5 4d }

  condition:
    any of them
}