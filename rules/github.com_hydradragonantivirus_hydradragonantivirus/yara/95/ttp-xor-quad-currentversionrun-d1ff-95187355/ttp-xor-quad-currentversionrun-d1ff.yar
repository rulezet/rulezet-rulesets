rule TTP_XOR_QUAD_CurrentVersionRun_d1ff {
  strings:
    $key_d1ff = { 82 90 [2] a6 9e [2] 8d b2 [2] a3 90 [2] b7 8b [2] b8 91 [2] a6 8c [2] a4 8d [2] bf 8b [2] a3 8c [2] bf a3 }

  condition:
    any of them
}