rule TTP_XOR_QUAD_CurrentVersionRun_c404 {
  strings:
    $key_c404 = { 97 6b [2] b3 65 [2] 98 49 [2] b6 6b [2] a2 70 [2] ad 6a [2] b3 77 [2] b1 76 [2] aa 70 [2] b6 77 [2] aa 58 }

  condition:
    any of them
}