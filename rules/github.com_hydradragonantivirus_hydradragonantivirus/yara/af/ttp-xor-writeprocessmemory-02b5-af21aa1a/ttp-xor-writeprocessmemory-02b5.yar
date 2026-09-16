rule TTP_XOR_WriteProcessMemory_02b5 {
  strings:
    $key_02b5 = { 55 c7 [2] 67 e5 [2] 61 d0 [2] 4f d0 [2] 70 cc }

  condition:
    any of them
}