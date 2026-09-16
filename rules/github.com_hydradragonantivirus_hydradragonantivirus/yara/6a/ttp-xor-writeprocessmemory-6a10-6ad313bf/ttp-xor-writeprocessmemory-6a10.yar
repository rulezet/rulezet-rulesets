rule TTP_XOR_WriteProcessMemory_6a10 {
  strings:
    $key_6a10 = { 3d 62 [2] 0f 40 [2] 09 75 [2] 27 75 [2] 18 69 }

  condition:
    any of them
}