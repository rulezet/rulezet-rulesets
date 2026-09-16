rule TTP_XOR_QUAD_CurrentVersionRun_180e {
  strings:
    $key_180e = { 4b 61 [2] 6f 6f [2] 44 43 [2] 6a 61 [2] 7e 7a [2] 71 60 [2] 6f 7d [2] 6d 7c [2] 76 7a [2] 6a 7d [2] 76 52 }

  condition:
    any of them
}