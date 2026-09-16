rule TTP_XOR_WriteProcessMemory_7696 {
  strings:
    $key_7696 = { 21 e4 [2] 13 c6 [2] 15 f3 [2] 3b f3 [2] 04 ef }

  condition:
    any of them
}