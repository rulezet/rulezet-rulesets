rule TTP_XOR_QUAD_CurrentVersionRun_3d6a {
  strings:
    $key_3d6a = { 6e 05 [2] 4a 0b [2] 61 27 [2] 4f 05 [2] 5b 1e [2] 54 04 [2] 4a 19 [2] 48 18 [2] 53 1e [2] 4f 19 [2] 53 36 }

  condition:
    any of them
}