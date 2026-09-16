rule TTP_XOR_QUAD_CurrentVersionRun_04fe {
  strings:
    $key_04fe = { 57 91 [2] 73 9f [2] 58 b3 [2] 76 91 [2] 62 8a [2] 6d 90 [2] 73 8d [2] 71 8c [2] 6a 8a [2] 76 8d [2] 6a a2 }

  condition:
    any of them
}