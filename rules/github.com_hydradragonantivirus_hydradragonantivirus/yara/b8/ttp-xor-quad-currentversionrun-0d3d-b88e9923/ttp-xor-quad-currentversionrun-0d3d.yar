rule TTP_XOR_QUAD_CurrentVersionRun_0d3d {
  strings:
    $key_0d3d = { 5e 52 [2] 7a 5c [2] 51 70 [2] 7f 52 [2] 6b 49 [2] 64 53 [2] 7a 4e [2] 78 4f [2] 63 49 [2] 7f 4e [2] 63 61 }

  condition:
    any of them
}