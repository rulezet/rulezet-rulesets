rule TTP_XOR_QUAD_CurrentVersionRun_630e {
  strings:
    $key_630e = { 30 61 [2] 14 6f [2] 3f 43 [2] 11 61 [2] 05 7a [2] 0a 60 [2] 14 7d [2] 16 7c [2] 0d 7a [2] 11 7d [2] 0d 52 }

  condition:
    any of them
}