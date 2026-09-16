rule TTP_XOR_WriteProcessMemory_0196 {
  strings:
    $key_0196 = { 56 e4 [2] 64 c6 [2] 62 f3 [2] 4c f3 [2] 73 ef }

  condition:
    any of them
}