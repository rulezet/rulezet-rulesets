rule TTP_XOR_QUAD_CurrentVersionRun_3a0e {
  strings:
    $key_3a0e = { 69 61 [2] 4d 6f [2] 66 43 [2] 48 61 [2] 5c 7a [2] 53 60 [2] 4d 7d [2] 4f 7c [2] 54 7a [2] 48 7d [2] 54 52 }

  condition:
    any of them
}