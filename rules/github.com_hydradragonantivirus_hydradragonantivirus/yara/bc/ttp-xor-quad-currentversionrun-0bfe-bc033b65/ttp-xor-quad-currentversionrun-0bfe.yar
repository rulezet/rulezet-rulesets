rule TTP_XOR_QUAD_CurrentVersionRun_0bfe {
  strings:
    $key_0bfe = { 58 91 [2] 7c 9f [2] 57 b3 [2] 79 91 [2] 6d 8a [2] 62 90 [2] 7c 8d [2] 7e 8c [2] 65 8a [2] 79 8d [2] 65 a2 }

  condition:
    any of them
}