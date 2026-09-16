rule TTP_XOR_QUAD_CurrentVersionRun_2619 {
  strings:
    $key_2619 = { 75 76 [2] 51 78 [2] 7a 54 [2] 54 76 [2] 40 6d [2] 4f 77 [2] 51 6a [2] 53 6b [2] 48 6d [2] 54 6a [2] 48 45 }

  condition:
    any of them
}