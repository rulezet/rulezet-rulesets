rule TTP_XOR_WriteProcessMemory_20b5 {
  strings:
    $key_20b5 = { 77 c7 [2] 45 e5 [2] 43 d0 [2] 6d d0 [2] 52 cc }

  condition:
    any of them
}