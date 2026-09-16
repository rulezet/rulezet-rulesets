rule TTP_XOR_QUAD_CurrentVersionRun_3d3a {
  strings:
    $key_3d3a = { 6e 55 [2] 4a 5b [2] 61 77 [2] 4f 55 [2] 5b 4e [2] 54 54 [2] 4a 49 [2] 48 48 [2] 53 4e [2] 4f 49 [2] 53 66 }

  condition:
    any of them
}