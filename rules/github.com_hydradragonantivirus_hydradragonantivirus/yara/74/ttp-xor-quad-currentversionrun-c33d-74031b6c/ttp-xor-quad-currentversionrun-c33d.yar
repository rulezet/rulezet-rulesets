rule TTP_XOR_QUAD_CurrentVersionRun_c33d {
  strings:
    $key_c33d = { 90 52 [2] b4 5c [2] 9f 70 [2] b1 52 [2] a5 49 [2] aa 53 [2] b4 4e [2] b6 4f [2] ad 49 [2] b1 4e [2] ad 61 }

  condition:
    any of them
}