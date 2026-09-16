rule TTP_XOR_WriteProcessMemory_7c97 {
  strings:
    $key_7c97 = { 2b e5 [2] 19 c7 [2] 1f f2 [2] 31 f2 [2] 0e ee }

  condition:
    any of them
}