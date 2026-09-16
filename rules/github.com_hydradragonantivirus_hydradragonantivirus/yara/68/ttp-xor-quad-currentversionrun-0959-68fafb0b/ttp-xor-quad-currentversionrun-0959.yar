rule TTP_XOR_QUAD_CurrentVersionRun_0959 {
  strings:
    $key_0959 = { 5a 36 [2] 7e 38 [2] 55 14 [2] 7b 36 [2] 6f 2d [2] 60 37 [2] 7e 2a [2] 7c 2b [2] 67 2d [2] 7b 2a [2] 67 05 }

  condition:
    any of them
}