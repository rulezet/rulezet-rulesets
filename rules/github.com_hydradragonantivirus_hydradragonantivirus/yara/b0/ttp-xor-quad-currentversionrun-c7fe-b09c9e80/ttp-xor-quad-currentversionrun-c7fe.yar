rule TTP_XOR_QUAD_CurrentVersionRun_c7fe {
  strings:
    $key_c7fe = { 94 91 [2] b0 9f [2] 9b b3 [2] b5 91 [2] a1 8a [2] ae 90 [2] b0 8d [2] b2 8c [2] a9 8a [2] b5 8d [2] a9 a2 }

  condition:
    any of them
}