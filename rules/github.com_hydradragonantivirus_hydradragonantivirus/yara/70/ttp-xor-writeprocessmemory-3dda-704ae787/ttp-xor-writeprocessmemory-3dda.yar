rule TTP_XOR_WriteProcessMemory_3dda {
  strings:
    $key_3dda = { 6a a8 [2] 58 8a [2] 5e bf [2] 70 bf [2] 4f a3 }

  condition:
    any of them
}