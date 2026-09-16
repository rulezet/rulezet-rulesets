rule TTP_XOR_QUAD_CurrentVersionRun_d4fe {
  strings:
    $key_d4fe = { 87 91 [2] a3 9f [2] 88 b3 [2] a6 91 [2] b2 8a [2] bd 90 [2] a3 8d [2] a1 8c [2] ba 8a [2] a6 8d [2] ba a2 }

  condition:
    any of them
}