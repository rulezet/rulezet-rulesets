rule TTP_XOR_WriteProcessMemory_8a74 {
  strings:
    $key_8a74 = { dd 06 [2] ef 24 [2] e9 11 [2] c7 11 [2] f8 0d }

  condition:
    any of them
}