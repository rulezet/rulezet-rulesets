rule TTP_XOR_WriteProcessMemory_7094 {
  strings:
    $key_7094 = { 27 e6 [2] 15 c4 [2] 13 f1 [2] 3d f1 [2] 02 ed }

  condition:
    any of them
}