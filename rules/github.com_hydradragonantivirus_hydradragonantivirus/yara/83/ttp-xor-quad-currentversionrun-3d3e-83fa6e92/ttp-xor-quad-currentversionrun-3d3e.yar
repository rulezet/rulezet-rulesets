rule TTP_XOR_QUAD_CurrentVersionRun_3d3e {
  strings:
    $key_3d3e = { 6e 51 [2] 4a 5f [2] 61 73 [2] 4f 51 [2] 5b 4a [2] 54 50 [2] 4a 4d [2] 48 4c [2] 53 4a [2] 4f 4d [2] 53 62 }

  condition:
    any of them
}