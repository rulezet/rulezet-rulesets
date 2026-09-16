rule TTP_XOR_QUAD_CurrentVersionRun_12b2 {
  strings:
    $key_12b2 = { 41 dd [2] 65 d3 [2] 4e ff [2] 60 dd [2] 74 c6 [2] 7b dc [2] 65 c1 [2] 67 c0 [2] 7c c6 [2] 60 c1 [2] 7c ee }

  condition:
    any of them
}