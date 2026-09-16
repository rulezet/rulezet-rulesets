rule TTP_XOR_WriteProcessMemory_8744 {
  strings:
    $key_8744 = { d0 36 [2] e2 14 [2] e4 21 [2] ca 21 [2] f5 3d }

  condition:
    any of them
}