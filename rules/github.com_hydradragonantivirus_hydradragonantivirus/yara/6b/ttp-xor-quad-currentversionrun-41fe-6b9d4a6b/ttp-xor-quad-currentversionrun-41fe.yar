rule TTP_XOR_QUAD_CurrentVersionRun_41fe {
  strings:
    $key_41fe = { 12 91 [2] 36 9f [2] 1d b3 [2] 33 91 [2] 27 8a [2] 28 90 [2] 36 8d [2] 34 8c [2] 2f 8a [2] 33 8d [2] 2f a2 }

  condition:
    any of them
}