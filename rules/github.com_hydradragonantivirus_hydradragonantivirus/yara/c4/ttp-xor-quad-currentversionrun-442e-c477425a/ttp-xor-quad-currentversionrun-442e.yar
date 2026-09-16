rule TTP_XOR_QUAD_CurrentVersionRun_442e {
  strings:
    $key_442e = { 17 41 [2] 33 4f [2] 18 63 [2] 36 41 [2] 22 5a [2] 2d 40 [2] 33 5d [2] 31 5c [2] 2a 5a [2] 36 5d [2] 2a 72 }

  condition:
    any of them
}