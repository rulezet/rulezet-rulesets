rule TTP_XOR_WriteProcessMemory_03b5 {
  strings:
    $key_03b5 = { 54 c7 [2] 66 e5 [2] 60 d0 [2] 4e d0 [2] 71 cc }

  condition:
    any of them
}