rule TTP_XOR_WriteProcessMemory_c6b6 {
  strings:
    $key_c6b6 = { 91 c4 [2] a3 e6 [2] a5 d3 [2] 8b d3 [2] b4 cf }

  condition:
    any of them
}