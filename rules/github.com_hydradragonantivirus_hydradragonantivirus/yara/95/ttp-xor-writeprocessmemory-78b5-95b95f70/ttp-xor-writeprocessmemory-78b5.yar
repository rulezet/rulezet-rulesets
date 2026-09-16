rule TTP_XOR_WriteProcessMemory_78b5 {
  strings:
    $key_78b5 = { 2f c7 [2] 1d e5 [2] 1b d0 [2] 35 d0 [2] 0a cc }

  condition:
    any of them
}