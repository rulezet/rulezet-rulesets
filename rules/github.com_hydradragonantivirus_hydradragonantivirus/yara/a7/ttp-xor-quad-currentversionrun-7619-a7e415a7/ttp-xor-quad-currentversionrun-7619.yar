rule TTP_XOR_QUAD_CurrentVersionRun_7619 {
  strings:
    $key_7619 = { 25 76 [2] 01 78 [2] 2a 54 [2] 04 76 [2] 10 6d [2] 1f 77 [2] 01 6a [2] 03 6b [2] 18 6d [2] 04 6a [2] 18 45 }

  condition:
    any of them
}