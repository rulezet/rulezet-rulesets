rule TTP_XOR_WriteProcessMemory_ebb6 {
  strings:
    $key_ebb6 = { bc c4 [2] 8e e6 [2] 88 d3 [2] a6 d3 [2] 99 cf }

  condition:
    any of them
}