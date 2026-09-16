rule TTP_XOR_WriteProcessMemory_6ac5 {
  strings:
    $key_6ac5 = { 3d b7 [2] 0f 95 [2] 09 a0 [2] 27 a0 [2] 18 bc }

  condition:
    any of them
}