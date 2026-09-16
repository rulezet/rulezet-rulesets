rule TTP_XOR_WriteProcessMemory_4ab5 {
  strings:
    $key_4ab5 = { 1d c7 [2] 2f e5 [2] 29 d0 [2] 07 d0 [2] 38 cc }

  condition:
    any of them
}