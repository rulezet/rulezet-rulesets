rule TTP_XOR_QUAD_CurrentVersionRun_62b2 {
  strings:
    $key_62b2 = { 31 dd [2] 15 d3 [2] 3e ff [2] 10 dd [2] 04 c6 [2] 0b dc [2] 15 c1 [2] 17 c0 [2] 0c c6 [2] 10 c1 [2] 0c ee }

  condition:
    any of them
}