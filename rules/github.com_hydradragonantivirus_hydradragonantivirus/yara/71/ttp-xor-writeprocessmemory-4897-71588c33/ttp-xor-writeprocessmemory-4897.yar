rule TTP_XOR_WriteProcessMemory_4897 {
  strings:
    $key_4897 = { 1f e5 [2] 2d c7 [2] 2b f2 [2] 05 f2 [2] 3a ee }

  condition:
    any of them
}