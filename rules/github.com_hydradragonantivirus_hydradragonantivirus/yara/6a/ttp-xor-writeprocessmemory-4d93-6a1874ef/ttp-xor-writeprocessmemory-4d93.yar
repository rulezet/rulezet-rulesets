rule TTP_XOR_WriteProcessMemory_4d93 {
  strings:
    $key_4d93 = { 1a e1 [2] 28 c3 [2] 2e f6 [2] 00 f6 [2] 3f ea }

  condition:
    any of them
}