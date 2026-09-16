rule TTP_XOR_QUAD_CurrentVersionRun_c40c {
  strings:
    $key_c40c = { 97 63 [2] b3 6d [2] 98 41 [2] b6 63 [2] a2 78 [2] ad 62 [2] b3 7f [2] b1 7e [2] aa 78 [2] b6 7f [2] aa 50 }

  condition:
    any of them
}