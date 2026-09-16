rule TTP_XOR_WriteProcessMemory_0ea2 {
  strings:
    $key_0ea2 = { 59 d0 [2] 6b f2 [2] 6d c7 [2] 43 c7 [2] 7c db }

  condition:
    any of them
}