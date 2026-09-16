rule TTP_XOR_WriteProcessMemory_4c97 {
  strings:
    $key_4c97 = { 1b e5 [2] 29 c7 [2] 2f f2 [2] 01 f2 [2] 3e ee }

  condition:
    any of them
}