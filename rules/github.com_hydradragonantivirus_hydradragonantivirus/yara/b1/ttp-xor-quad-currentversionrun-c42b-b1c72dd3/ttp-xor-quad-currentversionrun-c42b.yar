rule TTP_XOR_QUAD_CurrentVersionRun_c42b {
  strings:
    $key_c42b = { 97 44 [2] b3 4a [2] 98 66 [2] b6 44 [2] a2 5f [2] ad 45 [2] b3 58 [2] b1 59 [2] aa 5f [2] b6 58 [2] aa 77 }

  condition:
    any of them
}