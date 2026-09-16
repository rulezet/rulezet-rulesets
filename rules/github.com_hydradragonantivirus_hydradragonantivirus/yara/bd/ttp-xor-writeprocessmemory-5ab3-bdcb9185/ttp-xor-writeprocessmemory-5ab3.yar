rule TTP_XOR_WriteProcessMemory_5ab3 {
  strings:
    $key_5ab3 = { 0d c1 [2] 3f e3 [2] 39 d6 [2] 17 d6 [2] 28 ca }

  condition:
    any of them
}