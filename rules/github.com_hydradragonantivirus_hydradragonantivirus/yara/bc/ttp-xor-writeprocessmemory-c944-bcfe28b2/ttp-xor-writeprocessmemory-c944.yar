rule TTP_XOR_WriteProcessMemory_c944 {
  strings:
    $key_c944 = { 9e 36 [2] ac 14 [2] aa 21 [2] 84 21 [2] bb 3d }

  condition:
    any of them
}