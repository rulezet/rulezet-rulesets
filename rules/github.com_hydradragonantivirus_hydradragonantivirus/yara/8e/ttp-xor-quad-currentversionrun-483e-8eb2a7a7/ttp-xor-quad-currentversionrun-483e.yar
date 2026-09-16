rule TTP_XOR_QUAD_CurrentVersionRun_483e {
  strings:
    $key_483e = { 1b 51 [2] 3f 5f [2] 14 73 [2] 3a 51 [2] 2e 4a [2] 21 50 [2] 3f 4d [2] 3d 4c [2] 26 4a [2] 3a 4d [2] 26 62 }

  condition:
    any of them
}