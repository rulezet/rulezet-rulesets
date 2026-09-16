rule TTP_XOR_WriteProcessMemory_3d03 {
  strings:
    $key_3d03 = { 6a 71 [2] 58 53 [2] 5e 66 [2] 70 66 [2] 4f 7a }

  condition:
    any of them
}