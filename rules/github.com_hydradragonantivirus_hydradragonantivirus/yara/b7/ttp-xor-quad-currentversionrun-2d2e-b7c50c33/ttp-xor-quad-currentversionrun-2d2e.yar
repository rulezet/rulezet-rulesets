rule TTP_XOR_QUAD_CurrentVersionRun_2d2e {
  strings:
    $key_2d2e = { 7e 41 [2] 5a 4f [2] 71 63 [2] 5f 41 [2] 4b 5a [2] 44 40 [2] 5a 5d [2] 58 5c [2] 43 5a [2] 5f 5d [2] 43 72 }

  condition:
    any of them
}