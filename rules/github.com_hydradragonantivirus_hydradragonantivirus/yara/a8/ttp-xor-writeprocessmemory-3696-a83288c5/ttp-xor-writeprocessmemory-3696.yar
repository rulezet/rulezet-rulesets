rule TTP_XOR_WriteProcessMemory_3696 {
  strings:
    $key_3696 = { 61 e4 [2] 53 c6 [2] 55 f3 [2] 7b f3 [2] 44 ef }

  condition:
    any of them
}