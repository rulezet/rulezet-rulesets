rule TTP_XOR_QUAD_CurrentVersionRun_431e {
  strings:
    $key_431e = { 10 71 [2] 34 7f [2] 1f 53 [2] 31 71 [2] 25 6a [2] 2a 70 [2] 34 6d [2] 36 6c [2] 2d 6a [2] 31 6d [2] 2d 42 }

  condition:
    any of them
}