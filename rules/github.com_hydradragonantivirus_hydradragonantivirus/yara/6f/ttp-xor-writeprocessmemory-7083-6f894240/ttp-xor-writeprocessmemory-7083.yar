rule TTP_XOR_WriteProcessMemory_7083 {
  strings:
    $key_7083 = { 27 f1 [2] 15 d3 [2] 13 e6 [2] 3d e6 [2] 02 fa }

  condition:
    any of them
}