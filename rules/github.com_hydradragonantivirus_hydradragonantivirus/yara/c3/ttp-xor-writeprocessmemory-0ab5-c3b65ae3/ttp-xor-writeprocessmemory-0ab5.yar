rule TTP_XOR_WriteProcessMemory_0ab5 {
  strings:
    $key_0ab5 = { 5d c7 [2] 6f e5 [2] 69 d0 [2] 47 d0 [2] 78 cc }

  condition:
    any of them
}