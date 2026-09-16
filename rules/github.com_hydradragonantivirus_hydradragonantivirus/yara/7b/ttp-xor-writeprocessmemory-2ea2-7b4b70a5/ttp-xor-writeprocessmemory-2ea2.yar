rule TTP_XOR_WriteProcessMemory_2ea2 {
  strings:
    $key_2ea2 = { 79 d0 [2] 4b f2 [2] 4d c7 [2] 63 c7 [2] 5c db }

  condition:
    any of them
}