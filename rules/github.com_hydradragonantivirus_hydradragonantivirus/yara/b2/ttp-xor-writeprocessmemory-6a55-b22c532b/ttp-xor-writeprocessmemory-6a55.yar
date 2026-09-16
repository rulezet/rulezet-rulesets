rule TTP_XOR_WriteProcessMemory_6a55 {
  strings:
    $key_6a55 = { 3d 27 [2] 0f 05 [2] 09 30 [2] 27 30 [2] 18 2c }

  condition:
    any of them
}