rule TTP_XOR_WriteProcessMemory_3bb6 {
  strings:
    $key_3bb6 = { 6c c4 [2] 5e e6 [2] 58 d3 [2] 76 d3 [2] 49 cf }

  condition:
    any of them
}