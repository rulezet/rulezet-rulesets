rule TTP_XOR_QUAD_CurrentVersionRun_c60f {
  strings:
    $key_c60f = { 95 60 [2] b1 6e [2] 9a 42 [2] b4 60 [2] a0 7b [2] af 61 [2] b1 7c [2] b3 7d [2] a8 7b [2] b4 7c [2] a8 53 }

  condition:
    any of them
}