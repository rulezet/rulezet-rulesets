rule TTP_XOR_WriteProcessMemory_3690 {
  strings:
    $key_3690 = { 61 e2 [2] 53 c0 [2] 55 f5 [2] 7b f5 [2] 44 e9 }

  condition:
    any of them
}