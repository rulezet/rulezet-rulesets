rule TTP_XOR_WriteProcessMemory_70c4 {
  strings:
    $key_70c4 = { 27 b6 [2] 15 94 [2] 13 a1 [2] 3d a1 [2] 02 bd }

  condition:
    any of them
}