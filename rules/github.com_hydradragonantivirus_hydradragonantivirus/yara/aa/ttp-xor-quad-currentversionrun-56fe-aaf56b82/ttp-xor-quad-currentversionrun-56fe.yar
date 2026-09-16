rule TTP_XOR_QUAD_CurrentVersionRun_56fe {
  strings:
    $key_56fe = { 05 91 [2] 21 9f [2] 0a b3 [2] 24 91 [2] 30 8a [2] 3f 90 [2] 21 8d [2] 23 8c [2] 38 8a [2] 24 8d [2] 38 a2 }

  condition:
    any of them
}