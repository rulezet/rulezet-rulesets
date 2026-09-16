rule TTP_XOR_QUAD_CurrentVersionRun_73fe {
  strings:
    $key_73fe = { 20 91 [2] 04 9f [2] 2f b3 [2] 01 91 [2] 15 8a [2] 1a 90 [2] 04 8d [2] 06 8c [2] 1d 8a [2] 01 8d [2] 1d a2 }

  condition:
    any of them
}