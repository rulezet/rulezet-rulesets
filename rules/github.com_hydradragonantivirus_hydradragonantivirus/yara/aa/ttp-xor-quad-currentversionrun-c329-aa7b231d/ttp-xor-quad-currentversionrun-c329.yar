rule TTP_XOR_QUAD_CurrentVersionRun_c329 {
  strings:
    $key_c329 = { 90 46 [2] b4 48 [2] 9f 64 [2] b1 46 [2] a5 5d [2] aa 47 [2] b4 5a [2] b6 5b [2] ad 5d [2] b1 5a [2] ad 75 }

  condition:
    any of them
}