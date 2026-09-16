rule TTP_XOR_QUAD_CurrentVersionRun_c40a {
  strings:
    $key_c40a = { 97 65 [2] b3 6b [2] 98 47 [2] b6 65 [2] a2 7e [2] ad 64 [2] b3 79 [2] b1 78 [2] aa 7e [2] b6 79 [2] aa 56 }

  condition:
    any of them
}