rule TTP_XOR_WriteProcessMemory_52b5 {
  strings:
    $key_52b5 = { 05 c7 [2] 37 e5 [2] 31 d0 [2] 1f d0 [2] 20 cc }

  condition:
    any of them
}