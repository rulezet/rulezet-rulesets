rule TTP_XOR_WriteProcessMemory_12b5 {
  strings:
    $key_12b5 = { 45 c7 [2] 77 e5 [2] 71 d0 [2] 5f d0 [2] 60 cc }

  condition:
    any of them
}