rule TTP_XOR_QUAD_CurrentVersionRun_c33c {
  strings:
    $key_c33c = { 90 53 [2] b4 5d [2] 9f 71 [2] b1 53 [2] a5 48 [2] aa 52 [2] b4 4f [2] b6 4e [2] ad 48 [2] b1 4f [2] ad 60 }

  condition:
    any of them
}