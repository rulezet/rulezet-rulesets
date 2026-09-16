rule TTP_XOR_WriteProcessMemory_6acd {
  strings:
    $key_6acd = { 3d bf [2] 0f 9d [2] 09 a8 [2] 27 a8 [2] 18 b4 }

  condition:
    any of them
}