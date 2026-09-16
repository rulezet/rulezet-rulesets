rule TTP_XOR_QUAD_CurrentVersionRun_374e {
  strings:
    $key_374e = { 64 21 [2] 40 2f [2] 6b 03 [2] 45 21 [2] 51 3a [2] 5e 20 [2] 40 3d [2] 42 3c [2] 59 3a [2] 45 3d [2] 59 12 }

  condition:
    any of them
}