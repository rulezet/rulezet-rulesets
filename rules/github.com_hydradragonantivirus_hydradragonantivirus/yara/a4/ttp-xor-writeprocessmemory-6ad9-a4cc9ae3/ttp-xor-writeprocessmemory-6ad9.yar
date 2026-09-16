rule TTP_XOR_WriteProcessMemory_6ad9 {
  strings:
    $key_6ad9 = { 3d ab [2] 0f 89 [2] 09 bc [2] 27 bc [2] 18 a0 }

  condition:
    any of them
}