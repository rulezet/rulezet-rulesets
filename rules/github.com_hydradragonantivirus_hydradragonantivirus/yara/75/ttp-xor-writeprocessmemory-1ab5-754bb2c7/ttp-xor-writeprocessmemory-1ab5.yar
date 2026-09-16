rule TTP_XOR_WriteProcessMemory_1ab5 {
  strings:
    $key_1ab5 = { 4d c7 [2] 7f e5 [2] 79 d0 [2] 57 d0 [2] 68 cc }

  condition:
    any of them
}