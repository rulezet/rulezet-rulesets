rule TTP_XOR_QUAD_CurrentVersionRun_43fe {
  strings:
    $key_43fe = { 10 91 [2] 34 9f [2] 1f b3 [2] 31 91 [2] 25 8a [2] 2a 90 [2] 34 8d [2] 36 8c [2] 2d 8a [2] 31 8d [2] 2d a2 }

  condition:
    any of them
}