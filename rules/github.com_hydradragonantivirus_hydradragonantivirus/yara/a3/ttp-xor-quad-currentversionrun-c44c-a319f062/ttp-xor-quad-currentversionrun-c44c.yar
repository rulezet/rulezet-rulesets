rule TTP_XOR_QUAD_CurrentVersionRun_c44c {
  strings:
    $key_c44c = { 97 23 [2] b3 2d [2] 98 01 [2] b6 23 [2] a2 38 [2] ad 22 [2] b3 3f [2] b1 3e [2] aa 38 [2] b6 3f [2] aa 10 }

  condition:
    any of them
}