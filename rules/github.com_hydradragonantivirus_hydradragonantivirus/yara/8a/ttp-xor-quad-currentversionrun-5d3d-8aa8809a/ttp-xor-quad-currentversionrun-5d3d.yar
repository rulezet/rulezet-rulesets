rule TTP_XOR_QUAD_CurrentVersionRun_5d3d {
  strings:
    $key_5d3d = { 0e 52 [2] 2a 5c [2] 01 70 [2] 2f 52 [2] 3b 49 [2] 34 53 [2] 2a 4e [2] 28 4f [2] 33 49 [2] 2f 4e [2] 33 61 }

  condition:
    any of them
}