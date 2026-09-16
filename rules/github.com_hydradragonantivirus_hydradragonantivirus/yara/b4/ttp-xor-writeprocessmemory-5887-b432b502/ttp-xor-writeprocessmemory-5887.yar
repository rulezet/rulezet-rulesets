rule TTP_XOR_WriteProcessMemory_5887 {
  strings:
    $key_5887 = { 0f f5 [2] 3d d7 [2] 3b e2 [2] 15 e2 [2] 2a fe }

  condition:
    any of them
}