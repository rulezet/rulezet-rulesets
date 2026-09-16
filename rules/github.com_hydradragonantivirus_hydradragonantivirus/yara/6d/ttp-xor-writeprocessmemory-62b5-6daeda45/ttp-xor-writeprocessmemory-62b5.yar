rule TTP_XOR_WriteProcessMemory_62b5 {
  strings:
    $key_62b5 = { 35 c7 [2] 07 e5 [2] 01 d0 [2] 2f d0 [2] 10 cc }

  condition:
    any of them
}