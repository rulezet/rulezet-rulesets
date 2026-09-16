rule TTP_XOR_WriteProcessMemory_5867 {
  strings:
    $key_5867 = { 0f 15 [2] 3d 37 [2] 3b 02 [2] 15 02 [2] 2a 1e }

  condition:
    any of them
}