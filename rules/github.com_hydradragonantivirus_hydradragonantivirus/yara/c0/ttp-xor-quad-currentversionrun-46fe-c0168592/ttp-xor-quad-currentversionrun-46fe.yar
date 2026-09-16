rule TTP_XOR_QUAD_CurrentVersionRun_46fe {
  strings:
    $key_46fe = { 15 91 [2] 31 9f [2] 1a b3 [2] 34 91 [2] 20 8a [2] 2f 90 [2] 31 8d [2] 33 8c [2] 28 8a [2] 34 8d [2] 28 a2 }

  condition:
    any of them
}