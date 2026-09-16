rule TTP_XOR_WriteProcessMemory_13b5 {
  strings:
    $key_13b5 = { 44 c7 [2] 76 e5 [2] 70 d0 [2] 5e d0 [2] 61 cc }

  condition:
    any of them
}