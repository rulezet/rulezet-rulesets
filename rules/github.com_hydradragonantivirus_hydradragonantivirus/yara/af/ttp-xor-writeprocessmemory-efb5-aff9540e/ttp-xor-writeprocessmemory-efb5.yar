rule TTP_XOR_WriteProcessMemory_efb5 {
  strings:
    $key_efb5 = { b8 c7 [2] 8a e5 [2] 8c d0 [2] a2 d0 [2] 9d cc }

  condition:
    any of them
}