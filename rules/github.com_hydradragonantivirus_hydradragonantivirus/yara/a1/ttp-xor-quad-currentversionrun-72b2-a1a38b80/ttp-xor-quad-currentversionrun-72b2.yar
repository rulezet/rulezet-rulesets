rule TTP_XOR_QUAD_CurrentVersionRun_72b2 {
  strings:
    $key_72b2 = { 21 dd [2] 05 d3 [2] 2e ff [2] 00 dd [2] 14 c6 [2] 1b dc [2] 05 c1 [2] 07 c0 [2] 1c c6 [2] 00 c1 [2] 1c ee }

  condition:
    any of them
}