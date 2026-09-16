rule TTP_XOR_QUAD_CurrentVersionRun_d1fe {
  strings:
    $key_d1fe = { 82 91 [2] a6 9f [2] 8d b3 [2] a3 91 [2] b7 8a [2] b8 90 [2] a6 8d [2] a4 8c [2] bf 8a [2] a3 8d [2] bf a2 }

  condition:
    any of them
}