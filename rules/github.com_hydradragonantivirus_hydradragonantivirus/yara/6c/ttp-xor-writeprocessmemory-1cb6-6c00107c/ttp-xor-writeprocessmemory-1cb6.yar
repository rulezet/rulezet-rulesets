rule TTP_XOR_WriteProcessMemory_1cb6 {
  strings:
    $key_1cb6 = { 4b c4 [2] 79 e6 [2] 7f d3 [2] 51 d3 [2] 6e cf }

  condition:
    any of them
}