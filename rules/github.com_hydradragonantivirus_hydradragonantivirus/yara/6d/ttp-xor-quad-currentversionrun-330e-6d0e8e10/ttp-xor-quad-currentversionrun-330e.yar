rule TTP_XOR_QUAD_CurrentVersionRun_330e {
  strings:
    $key_330e = { 60 61 [2] 44 6f [2] 6f 43 [2] 41 61 [2] 55 7a [2] 5a 60 [2] 44 7d [2] 46 7c [2] 5d 7a [2] 41 7d [2] 5d 52 }

  condition:
    any of them
}