rule TTP_XOR_QUAD_CurrentVersionRun_142e {
  strings:
    $key_142e = { 47 41 [2] 63 4f [2] 48 63 [2] 66 41 [2] 72 5a [2] 7d 40 [2] 63 5d [2] 61 5c [2] 7a 5a [2] 66 5d [2] 7a 72 }

  condition:
    any of them
}