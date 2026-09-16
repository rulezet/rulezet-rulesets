rule TTP_XOR_QUAD_CurrentVersionRun_d10f {
  strings:
    $key_d10f = { 82 60 [2] a6 6e [2] 8d 42 [2] a3 60 [2] b7 7b [2] b8 61 [2] a6 7c [2] a4 7d [2] bf 7b [2] a3 7c [2] bf 53 }

  condition:
    any of them
}