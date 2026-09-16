rule TTP_XOR_QUAD_CurrentVersionRun_310e {
  strings:
    $key_310e = { 62 61 [2] 46 6f [2] 6d 43 [2] 43 61 [2] 57 7a [2] 58 60 [2] 46 7d [2] 44 7c [2] 5f 7a [2] 43 7d [2] 5f 52 }

  condition:
    any of them
}