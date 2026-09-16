rule TTP_XOR_WriteProcessMemory_01b5 {
  strings:
    $key_01b5 = { 56 c7 [2] 64 e5 [2] 62 d0 [2] 4c d0 [2] 73 cc }

  condition:
    any of them
}