rule TTP_XOR_WriteProcessMemory_0344 {
  strings:
    $key_0344 = { 54 36 [2] 66 14 [2] 60 21 [2] 4e 21 [2] 71 3d }

  condition:
    any of them
}