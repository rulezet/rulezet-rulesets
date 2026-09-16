rule TTP_XOR_WriteProcessMemory_3ddd {
  strings:
    $key_3ddd = { 6a af [2] 58 8d [2] 5e b8 [2] 70 b8 [2] 4f a4 }

  condition:
    any of them
}