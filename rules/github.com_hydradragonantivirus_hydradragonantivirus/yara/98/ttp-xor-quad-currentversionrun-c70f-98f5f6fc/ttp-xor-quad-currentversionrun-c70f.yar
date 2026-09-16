rule TTP_XOR_QUAD_CurrentVersionRun_c70f {
  strings:
    $key_c70f = { 94 60 [2] b0 6e [2] 9b 42 [2] b5 60 [2] a1 7b [2] ae 61 [2] b0 7c [2] b2 7d [2] a9 7b [2] b5 7c [2] a9 53 }

  condition:
    any of them
}