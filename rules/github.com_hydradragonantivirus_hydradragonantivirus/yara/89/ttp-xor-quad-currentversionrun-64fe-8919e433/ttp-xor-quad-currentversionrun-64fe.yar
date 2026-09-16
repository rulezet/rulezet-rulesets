rule TTP_XOR_QUAD_CurrentVersionRun_64fe {
  strings:
    $key_64fe = { 37 91 [2] 13 9f [2] 38 b3 [2] 16 91 [2] 02 8a [2] 0d 90 [2] 13 8d [2] 11 8c [2] 0a 8a [2] 16 8d [2] 0a a2 }

  condition:
    any of them
}