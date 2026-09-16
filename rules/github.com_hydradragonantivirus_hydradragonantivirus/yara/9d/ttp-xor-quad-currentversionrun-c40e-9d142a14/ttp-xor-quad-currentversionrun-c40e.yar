rule TTP_XOR_QUAD_CurrentVersionRun_c40e {
  strings:
    $key_c40e = { 97 61 [2] b3 6f [2] 98 43 [2] b6 61 [2] a2 7a [2] ad 60 [2] b3 7d [2] b1 7c [2] aa 7a [2] b6 7d [2] aa 52 }

  condition:
    any of them
}