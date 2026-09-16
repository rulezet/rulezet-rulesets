rule TTP_XOR_WriteProcessMemory_7093 {
  strings:
    $key_7093 = { 27 e1 [2] 15 c3 [2] 13 f6 [2] 3d f6 [2] 02 ea }

  condition:
    any of them
}