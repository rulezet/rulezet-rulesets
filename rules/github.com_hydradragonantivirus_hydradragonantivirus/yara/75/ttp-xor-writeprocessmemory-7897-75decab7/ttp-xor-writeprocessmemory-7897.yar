rule TTP_XOR_WriteProcessMemory_7897 {
  strings:
    $key_7897 = { 2f e5 [2] 1d c7 [2] 1b f2 [2] 35 f2 [2] 0a ee }

  condition:
    any of them
}