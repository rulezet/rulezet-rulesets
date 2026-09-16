rule TTP_XOR_WriteProcessMemory_7085 {
  strings:
    $key_7085 = { 27 f7 [2] 15 d5 [2] 13 e0 [2] 3d e0 [2] 02 fc }

  condition:
    any of them
}