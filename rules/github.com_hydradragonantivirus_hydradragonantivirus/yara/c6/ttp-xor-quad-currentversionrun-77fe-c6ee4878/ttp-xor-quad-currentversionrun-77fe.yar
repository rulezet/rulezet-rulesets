rule TTP_XOR_QUAD_CurrentVersionRun_77fe {
  strings:
    $key_77fe = { 24 91 [2] 00 9f [2] 2b b3 [2] 05 91 [2] 11 8a [2] 1e 90 [2] 00 8d [2] 02 8c [2] 19 8a [2] 05 8d [2] 19 a2 }

  condition:
    any of them
}