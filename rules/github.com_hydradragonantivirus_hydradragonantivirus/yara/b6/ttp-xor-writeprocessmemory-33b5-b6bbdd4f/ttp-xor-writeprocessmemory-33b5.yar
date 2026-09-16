rule TTP_XOR_WriteProcessMemory_33b5 {
  strings:
    $key_33b5 = { 64 c7 [2] 56 e5 [2] 50 d0 [2] 7e d0 [2] 41 cc }

  condition:
    any of them
}