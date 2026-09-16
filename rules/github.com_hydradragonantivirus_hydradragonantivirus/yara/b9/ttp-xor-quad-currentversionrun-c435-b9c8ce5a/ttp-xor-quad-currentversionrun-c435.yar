rule TTP_XOR_QUAD_CurrentVersionRun_c435 {
  strings:
    $key_c435 = { 97 5a [2] b3 54 [2] 98 78 [2] b6 5a [2] a2 41 [2] ad 5b [2] b3 46 [2] b1 47 [2] aa 41 [2] b6 46 [2] aa 69 }

  condition:
    any of them
}