rule TTP_XOR_WriteProcessMemory_6a87 {
  strings:
    $key_6a87 = { 3d f5 [2] 0f d7 [2] 09 e2 [2] 27 e2 [2] 18 fe }

  condition:
    any of them
}