rule TTP_XOR_QUAD_CurrentVersionRun_c405 {
  strings:
    $key_c405 = { 97 6a [2] b3 64 [2] 98 48 [2] b6 6a [2] a2 71 [2] ad 6b [2] b3 76 [2] b1 77 [2] aa 71 [2] b6 76 [2] aa 59 }

  condition:
    any of them
}