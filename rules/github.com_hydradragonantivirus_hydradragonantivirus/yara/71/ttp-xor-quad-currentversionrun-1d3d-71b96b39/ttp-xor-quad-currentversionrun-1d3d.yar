rule TTP_XOR_QUAD_CurrentVersionRun_1d3d {
  strings:
    $key_1d3d = { 4e 52 [2] 6a 5c [2] 41 70 [2] 6f 52 [2] 7b 49 [2] 74 53 [2] 6a 4e [2] 68 4f [2] 73 49 [2] 6f 4e [2] 73 61 }

  condition:
    any of them
}