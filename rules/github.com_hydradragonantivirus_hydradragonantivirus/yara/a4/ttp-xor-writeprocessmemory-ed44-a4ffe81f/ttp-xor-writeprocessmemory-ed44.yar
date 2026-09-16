rule TTP_XOR_WriteProcessMemory_ed44 {
  strings:
    $key_ed44 = { ba 36 [2] 88 14 [2] 8e 21 [2] a0 21 [2] 9f 3d }

  condition:
    any of them
}