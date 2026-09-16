rule TTP_XOR_QUAD_CurrentVersionRun_480e {
  strings:
    $key_480e = { 1b 61 [2] 3f 6f [2] 14 43 [2] 3a 61 [2] 2e 7a [2] 21 60 [2] 3f 7d [2] 3d 7c [2] 26 7a [2] 3a 7d [2] 26 52 }

  condition:
    any of them
}