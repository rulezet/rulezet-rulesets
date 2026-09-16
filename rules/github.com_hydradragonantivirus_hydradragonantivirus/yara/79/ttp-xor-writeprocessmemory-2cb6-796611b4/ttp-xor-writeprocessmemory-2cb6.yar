rule TTP_XOR_WriteProcessMemory_2cb6 {
  strings:
    $key_2cb6 = { 7b c4 [2] 49 e6 [2] 4f d3 [2] 61 d3 [2] 5e cf }

  condition:
    any of them
}