rule TTP_XOR_QUAD_CurrentVersionRun_d819 {
  strings:
    $key_d819 = { 8b 76 [2] af 78 [2] 84 54 [2] aa 76 [2] be 6d [2] b1 77 [2] af 6a [2] ad 6b [2] b6 6d [2] aa 6a [2] b6 45 }

  condition:
    any of them
}