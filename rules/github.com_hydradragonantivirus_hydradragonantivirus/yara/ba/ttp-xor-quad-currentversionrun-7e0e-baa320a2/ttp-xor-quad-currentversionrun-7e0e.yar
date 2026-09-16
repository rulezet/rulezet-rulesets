rule TTP_XOR_QUAD_CurrentVersionRun_7e0e {
  strings:
    $key_7e0e = { 2d 61 [2] 09 6f [2] 22 43 [2] 0c 61 [2] 18 7a [2] 17 60 [2] 09 7d [2] 0b 7c [2] 10 7a [2] 0c 7d [2] 10 52 }

  condition:
    any of them
}