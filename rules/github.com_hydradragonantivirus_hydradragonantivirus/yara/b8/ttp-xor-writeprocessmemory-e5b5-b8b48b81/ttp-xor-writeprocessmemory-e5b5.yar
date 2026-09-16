rule TTP_XOR_WriteProcessMemory_e5b5 {
  strings:
    $key_e5b5 = { b2 c7 [2] 80 e5 [2] 86 d0 [2] a8 d0 [2] 97 cc }

  condition:
    any of them
}