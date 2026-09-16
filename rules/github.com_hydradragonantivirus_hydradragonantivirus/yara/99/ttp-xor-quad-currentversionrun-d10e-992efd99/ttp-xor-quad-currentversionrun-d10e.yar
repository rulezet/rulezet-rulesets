rule TTP_XOR_QUAD_CurrentVersionRun_d10e {
  strings:
    $key_d10e = { 82 61 [2] a6 6f [2] 8d 43 [2] a3 61 [2] b7 7a [2] b8 60 [2] a6 7d [2] a4 7c [2] bf 7a [2] a3 7d [2] bf 52 }

  condition:
    any of them
}