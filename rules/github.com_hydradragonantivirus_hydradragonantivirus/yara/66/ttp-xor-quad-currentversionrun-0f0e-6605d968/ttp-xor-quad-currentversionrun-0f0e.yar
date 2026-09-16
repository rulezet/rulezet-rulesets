rule TTP_XOR_QUAD_CurrentVersionRun_0f0e {
  strings:
    $key_0f0e = { 5c 61 [2] 78 6f [2] 53 43 [2] 7d 61 [2] 69 7a [2] 66 60 [2] 78 7d [2] 7a 7c [2] 61 7a [2] 7d 7d [2] 61 52 }

  condition:
    any of them
}