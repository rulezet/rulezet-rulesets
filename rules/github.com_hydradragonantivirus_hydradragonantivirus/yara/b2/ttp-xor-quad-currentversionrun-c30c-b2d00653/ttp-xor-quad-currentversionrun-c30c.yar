rule TTP_XOR_QUAD_CurrentVersionRun_c30c {
  strings:
    $key_c30c = { 90 63 [2] b4 6d [2] 9f 41 [2] b1 63 [2] a5 78 [2] aa 62 [2] b4 7f [2] b6 7e [2] ad 78 [2] b1 7f [2] ad 50 }

  condition:
    any of them
}