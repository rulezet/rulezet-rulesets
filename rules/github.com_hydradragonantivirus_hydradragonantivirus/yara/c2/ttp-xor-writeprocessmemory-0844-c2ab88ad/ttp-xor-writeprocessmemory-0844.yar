rule TTP_XOR_WriteProcessMemory_0844 {
  strings:
    $key_0844 = { 5f 36 [2] 6d 14 [2] 6b 21 [2] 45 21 [2] 7a 3d }

  condition:
    any of them
}