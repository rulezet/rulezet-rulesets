rule TTP_XOR_WriteProcessMemory_7c94 {
  strings:
    $key_7c94 = { 2b e6 [2] 19 c4 [2] 1f f1 [2] 31 f1 [2] 0e ed }

  condition:
    any of them
}