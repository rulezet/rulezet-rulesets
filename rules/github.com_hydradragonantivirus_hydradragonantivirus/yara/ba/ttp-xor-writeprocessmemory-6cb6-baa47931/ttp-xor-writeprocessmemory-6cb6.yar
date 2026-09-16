rule TTP_XOR_WriteProcessMemory_6cb6 {
  strings:
    $key_6cb6 = { 3b c4 [2] 09 e6 [2] 0f d3 [2] 21 d3 [2] 1e cf }

  condition:
    any of them
}