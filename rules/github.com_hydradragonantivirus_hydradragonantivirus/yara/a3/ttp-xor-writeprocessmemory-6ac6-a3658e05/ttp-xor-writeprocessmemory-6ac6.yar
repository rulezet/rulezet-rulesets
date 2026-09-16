rule TTP_XOR_WriteProcessMemory_6ac6 {
  strings:
    $key_6ac6 = { 3d b4 [2] 0f 96 [2] 09 a3 [2] 27 a3 [2] 18 bf }

  condition:
    any of them
}