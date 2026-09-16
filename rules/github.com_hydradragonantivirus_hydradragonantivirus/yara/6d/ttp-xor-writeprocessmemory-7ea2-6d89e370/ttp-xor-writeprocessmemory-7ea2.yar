rule TTP_XOR_WriteProcessMemory_7ea2 {
  strings:
    $key_7ea2 = { 29 d0 [2] 1b f2 [2] 1d c7 [2] 33 c7 [2] 0c db }

  condition:
    any of them
}