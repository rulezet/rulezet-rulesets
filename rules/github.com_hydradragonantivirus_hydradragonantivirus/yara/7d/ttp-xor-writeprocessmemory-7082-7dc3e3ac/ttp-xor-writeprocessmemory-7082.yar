rule TTP_XOR_WriteProcessMemory_7082 {
  strings:
    $key_7082 = { 27 f0 [2] 15 d2 [2] 13 e7 [2] 3d e7 [2] 02 fb }

  condition:
    any of them
}