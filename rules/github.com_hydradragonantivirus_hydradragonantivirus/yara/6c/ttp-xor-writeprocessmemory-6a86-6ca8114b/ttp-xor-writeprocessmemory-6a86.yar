rule TTP_XOR_WriteProcessMemory_6a86 {
  strings:
    $key_6a86 = { 3d f4 [2] 0f d6 [2] 09 e3 [2] 27 e3 [2] 18 ff }

  condition:
    any of them
}