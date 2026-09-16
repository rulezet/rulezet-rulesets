rule TTP_XOR_WriteProcessMemory_6496 {
  strings:
    $key_6496 = { 33 e4 [2] 01 c6 [2] 07 f3 [2] 29 f3 [2] 16 ef }

  condition:
    any of them
}