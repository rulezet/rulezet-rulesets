rule TTP_XOR_WriteProcessMemory_0ab6 {
  strings:
    $key_0ab6 = { 5d c4 [2] 6f e6 [2] 69 d3 [2] 47 d3 [2] 78 cf }

  condition:
    any of them
}