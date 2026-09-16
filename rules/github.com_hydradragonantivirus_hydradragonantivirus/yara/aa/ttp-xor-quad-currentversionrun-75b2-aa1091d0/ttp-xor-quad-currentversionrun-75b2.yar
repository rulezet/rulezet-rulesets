rule TTP_XOR_QUAD_CurrentVersionRun_75b2 {
  strings:
    $key_75b2 = { 26 dd [2] 02 d3 [2] 29 ff [2] 07 dd [2] 13 c6 [2] 1c dc [2] 02 c1 [2] 00 c0 [2] 1b c6 [2] 07 c1 [2] 1b ee }

  condition:
    any of them
}