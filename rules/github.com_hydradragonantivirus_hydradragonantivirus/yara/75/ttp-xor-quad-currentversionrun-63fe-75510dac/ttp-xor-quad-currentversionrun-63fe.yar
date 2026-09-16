rule TTP_XOR_QUAD_CurrentVersionRun_63fe {
  strings:
    $key_63fe = { 30 91 [2] 14 9f [2] 3f b3 [2] 11 91 [2] 05 8a [2] 0a 90 [2] 14 8d [2] 16 8c [2] 0d 8a [2] 11 8d [2] 0d a2 }

  condition:
    any of them
}