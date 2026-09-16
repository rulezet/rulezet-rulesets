rule TTP_XOR_QUAD_CurrentVersionRun_07fe {
  strings:
    $key_07fe = { 54 91 [2] 70 9f [2] 5b b3 [2] 75 91 [2] 61 8a [2] 6e 90 [2] 70 8d [2] 72 8c [2] 69 8a [2] 75 8d [2] 69 a2 }

  condition:
    any of them
}