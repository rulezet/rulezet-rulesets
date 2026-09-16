rule TTP_XOR_QUAD_CurrentVersionRun_154e {
  strings:
    $key_154e = { 46 21 [2] 62 2f [2] 49 03 [2] 67 21 [2] 73 3a [2] 7c 20 [2] 62 3d [2] 60 3c [2] 7b 3a [2] 67 3d [2] 7b 12 }

  condition:
    any of them
}