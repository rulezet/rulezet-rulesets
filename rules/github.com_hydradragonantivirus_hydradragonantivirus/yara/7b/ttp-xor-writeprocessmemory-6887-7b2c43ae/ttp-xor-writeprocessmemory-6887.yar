rule TTP_XOR_WriteProcessMemory_6887 {
  strings:
    $key_6887 = { 3f f5 [2] 0d d7 [2] 0b e2 [2] 25 e2 [2] 1a fe }

  condition:
    any of them
}