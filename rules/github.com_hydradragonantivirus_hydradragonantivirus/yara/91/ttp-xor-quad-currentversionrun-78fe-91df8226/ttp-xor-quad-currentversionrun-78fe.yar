rule TTP_XOR_QUAD_CurrentVersionRun_78fe {
  strings:
    $key_78fe = { 2b 91 [2] 0f 9f [2] 24 b3 [2] 0a 91 [2] 1e 8a [2] 11 90 [2] 0f 8d [2] 0d 8c [2] 16 8a [2] 0a 8d [2] 16 a2 }

  condition:
    any of them
}