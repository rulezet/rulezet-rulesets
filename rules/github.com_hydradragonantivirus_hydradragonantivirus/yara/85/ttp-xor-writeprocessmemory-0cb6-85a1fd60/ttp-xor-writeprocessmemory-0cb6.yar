rule TTP_XOR_WriteProcessMemory_0cb6 {
  strings:
    $key_0cb6 = { 5b c4 [2] 69 e6 [2] 6f d3 [2] 41 d3 [2] 7e cf }

  condition:
    any of them
}