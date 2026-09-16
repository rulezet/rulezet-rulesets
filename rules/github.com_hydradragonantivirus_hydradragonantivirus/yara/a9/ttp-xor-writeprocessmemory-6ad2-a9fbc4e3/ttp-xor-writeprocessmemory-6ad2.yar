rule TTP_XOR_WriteProcessMemory_6ad2 {
  strings:
    $key_6ad2 = { 3d a0 [2] 0f 82 [2] 09 b7 [2] 27 b7 [2] 18 ab }

  condition:
    any of them
}