rule TTP_XOR_WriteProcessMemory_47b5 {
  strings:
    $key_47b5 = { 10 c7 [2] 22 e5 [2] 24 d0 [2] 0a d0 [2] 35 cc }

  condition:
    any of them
}