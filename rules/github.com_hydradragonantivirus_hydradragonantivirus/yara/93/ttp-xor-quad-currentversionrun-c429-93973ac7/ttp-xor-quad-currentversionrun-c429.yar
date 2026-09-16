rule TTP_XOR_QUAD_CurrentVersionRun_c429 {
  strings:
    $key_c429 = { 97 46 [2] b3 48 [2] 98 64 [2] b6 46 [2] a2 5d [2] ad 47 [2] b3 5a [2] b1 5b [2] aa 5d [2] b6 5a [2] aa 75 }

  condition:
    any of them
}