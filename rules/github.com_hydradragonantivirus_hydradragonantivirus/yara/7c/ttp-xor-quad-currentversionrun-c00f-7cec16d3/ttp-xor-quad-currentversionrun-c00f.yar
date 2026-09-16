rule TTP_XOR_QUAD_CurrentVersionRun_c00f {
  strings:
    $key_c00f = { 93 60 [2] b7 6e [2] 9c 42 [2] b2 60 [2] a6 7b [2] a9 61 [2] b7 7c [2] b5 7d [2] ae 7b [2] b2 7c [2] ae 53 }

  condition:
    any of them
}