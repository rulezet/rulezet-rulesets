rule TTP_XOR_WriteProcessMemory_31b5 {
  strings:
    $key_31b5 = { 66 c7 [2] 54 e5 [2] 52 d0 [2] 7c d0 [2] 43 cc }

  condition:
    any of them
}