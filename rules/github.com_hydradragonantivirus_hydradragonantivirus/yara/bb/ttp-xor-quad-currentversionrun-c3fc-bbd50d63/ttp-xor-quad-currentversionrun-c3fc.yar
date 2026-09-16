rule TTP_XOR_QUAD_CurrentVersionRun_c3fc {
  strings:
    $key_c3fc = { 90 93 [2] b4 9d [2] 9f b1 [2] b1 93 [2] a5 88 [2] aa 92 [2] b4 8f [2] b6 8e [2] ad 88 [2] b1 8f [2] ad a0 }

  condition:
    any of them
}