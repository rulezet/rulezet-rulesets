rule TTP_XOR_WriteProcessMemory_e2b5 {
  strings:
    $key_e2b5 = { b5 c7 [2] 87 e5 [2] 81 d0 [2] af d0 [2] 90 cc }

  condition:
    any of them
}