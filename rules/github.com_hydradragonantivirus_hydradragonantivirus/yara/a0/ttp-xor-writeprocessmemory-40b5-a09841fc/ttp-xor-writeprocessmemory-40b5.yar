rule TTP_XOR_WriteProcessMemory_40b5 {
  strings:
    $key_40b5 = { 17 c7 [2] 25 e5 [2] 23 d0 [2] 0d d0 [2] 32 cc }

  condition:
    any of them
}