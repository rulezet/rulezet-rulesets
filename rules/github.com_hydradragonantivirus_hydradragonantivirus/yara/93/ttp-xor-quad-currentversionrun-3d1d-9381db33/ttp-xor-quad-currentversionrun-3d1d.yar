rule TTP_XOR_QUAD_CurrentVersionRun_3d1d {
  strings:
    $key_3d1d = { 6e 72 [2] 4a 7c [2] 61 50 [2] 4f 72 [2] 5b 69 [2] 54 73 [2] 4a 6e [2] 48 6f [2] 53 69 [2] 4f 6e [2] 53 41 }

  condition:
    any of them
}