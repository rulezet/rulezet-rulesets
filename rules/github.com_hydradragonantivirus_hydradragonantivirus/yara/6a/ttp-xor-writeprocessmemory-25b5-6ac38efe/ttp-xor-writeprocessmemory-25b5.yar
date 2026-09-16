rule TTP_XOR_WriteProcessMemory_25b5 {
  strings:
    $key_25b5 = { 72 c7 [2] 40 e5 [2] 46 d0 [2] 68 d0 [2] 57 cc }

  condition:
    any of them
}