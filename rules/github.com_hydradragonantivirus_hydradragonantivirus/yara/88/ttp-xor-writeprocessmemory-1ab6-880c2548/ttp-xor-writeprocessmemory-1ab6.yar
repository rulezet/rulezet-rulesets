rule TTP_XOR_WriteProcessMemory_1ab6 {
  strings:
    $key_1ab6 = { 4d c4 [2] 7f e6 [2] 79 d3 [2] 57 d3 [2] 68 cf }

  condition:
    any of them
}