rule TTP_XOR_QUAD_CurrentVersionRun_33fe {
  strings:
    $key_33fe = { 60 91 [2] 44 9f [2] 6f b3 [2] 41 91 [2] 55 8a [2] 5a 90 [2] 44 8d [2] 46 8c [2] 5d 8a [2] 41 8d [2] 5d a2 }

  condition:
    any of them
}