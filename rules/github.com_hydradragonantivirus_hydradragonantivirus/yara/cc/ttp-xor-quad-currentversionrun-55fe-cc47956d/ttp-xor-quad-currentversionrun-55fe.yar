rule TTP_XOR_QUAD_CurrentVersionRun_55fe {
  strings:
    $key_55fe = { 06 91 [2] 22 9f [2] 09 b3 [2] 27 91 [2] 33 8a [2] 3c 90 [2] 22 8d [2] 20 8c [2] 3b 8a [2] 27 8d [2] 3b a2 }

  condition:
    any of them
}