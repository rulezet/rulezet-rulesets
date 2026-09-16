rule TTP_XOR_WriteProcessMemory_7ab5 {
  strings:
    $key_7ab5 = { 2d c7 [2] 1f e5 [2] 19 d0 [2] 37 d0 [2] 08 cc }

  condition:
    any of them
}