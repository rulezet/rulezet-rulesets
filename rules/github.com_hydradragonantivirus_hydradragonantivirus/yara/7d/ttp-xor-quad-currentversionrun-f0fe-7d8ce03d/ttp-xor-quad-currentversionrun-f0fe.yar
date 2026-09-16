rule TTP_XOR_QUAD_CurrentVersionRun_f0fe {
  strings:
    $key_f0fe = { a3 91 [2] 87 9f [2] ac b3 [2] 82 91 [2] 96 8a [2] 99 90 [2] 87 8d [2] 85 8c [2] 9e 8a [2] 82 8d [2] 9e a2 }

  condition:
    any of them
}