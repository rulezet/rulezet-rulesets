rule TTP_XOR_QUAD_CurrentVersionRun_7d2e {
  strings:
    $key_7d2e = { 2e 41 [2] 0a 4f [2] 21 63 [2] 0f 41 [2] 1b 5a [2] 14 40 [2] 0a 5d [2] 08 5c [2] 13 5a [2] 0f 5d [2] 13 72 }

  condition:
    any of them
}