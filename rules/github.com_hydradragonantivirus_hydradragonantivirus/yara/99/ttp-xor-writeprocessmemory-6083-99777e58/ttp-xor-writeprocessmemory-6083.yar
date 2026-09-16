rule TTP_XOR_WriteProcessMemory_6083 {
  strings:
    $key_6083 = { 37 f1 [2] 05 d3 [2] 03 e6 [2] 2d e6 [2] 12 fa }

  condition:
    any of them
}