rule TTP_XOR_QUAD_CurrentVersionRun_486d {
  strings:
    $key_486d = { 1b 02 [2] 3f 0c [2] 14 20 [2] 3a 02 [2] 2e 19 [2] 21 03 [2] 3f 1e [2] 3d 1f [2] 26 19 [2] 3a 1e [2] 26 31 }

  condition:
    any of them
}