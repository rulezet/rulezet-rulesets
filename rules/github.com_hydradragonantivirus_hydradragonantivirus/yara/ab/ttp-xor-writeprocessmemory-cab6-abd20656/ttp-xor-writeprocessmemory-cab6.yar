rule TTP_XOR_WriteProcessMemory_cab6 {
  strings:
    $key_cab6 = { 9d c4 [2] af e6 [2] a9 d3 [2] 87 d3 [2] b8 cf }

  condition:
    any of them
}