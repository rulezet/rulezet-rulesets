rule TTP_XOR_QUAD_CurrentVersionRun_47fe {
  strings:
    $key_47fe = { 14 91 [2] 30 9f [2] 1b b3 [2] 35 91 [2] 21 8a [2] 2e 90 [2] 30 8d [2] 32 8c [2] 29 8a [2] 35 8d [2] 29 a2 }

  condition:
    any of them
}