rule TTP_XOR_WriteProcessMemory_3c94 {
  strings:
    $key_3c94 = { 6b e6 [2] 59 c4 [2] 5f f1 [2] 71 f1 [2] 4e ed }

  condition:
    any of them
}