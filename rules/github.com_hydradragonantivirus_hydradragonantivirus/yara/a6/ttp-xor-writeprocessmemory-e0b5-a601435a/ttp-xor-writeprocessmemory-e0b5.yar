rule TTP_XOR_WriteProcessMemory_e0b5 {
  strings:
    $key_e0b5 = { b7 c7 [2] 85 e5 [2] 83 d0 [2] ad d0 [2] 92 cc }

  condition:
    any of them
}