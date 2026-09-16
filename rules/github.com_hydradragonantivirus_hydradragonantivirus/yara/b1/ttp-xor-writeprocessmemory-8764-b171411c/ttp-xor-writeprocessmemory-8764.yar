rule TTP_XOR_WriteProcessMemory_8764 {
  strings:
    $key_8764 = { d0 16 [2] e2 34 [2] e4 01 [2] ca 01 [2] f5 1d }

  condition:
    any of them
}