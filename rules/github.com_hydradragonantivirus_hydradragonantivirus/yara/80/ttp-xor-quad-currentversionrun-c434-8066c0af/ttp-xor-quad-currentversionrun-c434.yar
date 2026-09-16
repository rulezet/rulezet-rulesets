rule TTP_XOR_QUAD_CurrentVersionRun_c434 {
  strings:
    $key_c434 = { 97 5b [2] b3 55 [2] 98 79 [2] b6 5b [2] a2 40 [2] ad 5a [2] b3 47 [2] b1 46 [2] aa 40 [2] b6 47 [2] aa 68 }

  condition:
    any of them
}