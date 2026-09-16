rule TTP_XOR_WriteProcessMemory_35b5 {
  strings:
    $key_35b5 = { 62 c7 [2] 50 e5 [2] 56 d0 [2] 78 d0 [2] 47 cc }

  condition:
    any of them
}