rule TTP_XOR_WriteProcessMemory_e7b5 {
  strings:
    $key_e7b5 = { b0 c7 [2] 82 e5 [2] 84 d0 [2] aa d0 [2] 95 cc }

  condition:
    any of them
}