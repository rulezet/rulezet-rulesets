rule TTP_XOR_WriteProcessMemory_4cb6 {
  strings:
    $key_4cb6 = { 1b c4 [2] 29 e6 [2] 2f d3 [2] 01 d3 [2] 3e cf }

  condition:
    any of them
}