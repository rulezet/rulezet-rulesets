rule TTP_XOR_WriteProcessMemory_42b5 {
  strings:
    $key_42b5 = { 15 c7 [2] 27 e5 [2] 21 d0 [2] 0f d0 [2] 30 cc }

  condition:
    any of them
}