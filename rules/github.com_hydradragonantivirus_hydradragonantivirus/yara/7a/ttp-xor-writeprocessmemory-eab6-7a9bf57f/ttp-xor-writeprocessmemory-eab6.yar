rule TTP_XOR_WriteProcessMemory_eab6 {
  strings:
    $key_eab6 = { bd c4 [2] 8f e6 [2] 89 d3 [2] a7 d3 [2] 98 cf }

  condition:
    any of them
}