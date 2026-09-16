rule TTP_XOR_QUAD_CurrentVersionRun_51fe {
  strings:
    $key_51fe = { 02 91 [2] 26 9f [2] 0d b3 [2] 23 91 [2] 37 8a [2] 38 90 [2] 26 8d [2] 24 8c [2] 3f 8a [2] 23 8d [2] 3f a2 }

  condition:
    any of them
}