rule TTP_XOR_QUAD_CurrentVersionRun_c0fe {
  strings:
    $key_c0fe = { 93 91 [2] b7 9f [2] 9c b3 [2] b2 91 [2] a6 8a [2] a9 90 [2] b7 8d [2] b5 8c [2] ae 8a [2] b2 8d [2] ae a2 }

  condition:
    any of them
}