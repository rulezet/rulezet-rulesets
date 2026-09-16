rule TTP_XOR_QUAD_CurrentVersionRun_7d7e {
  strings:
    $key_7d7e = { 2e 11 [2] 0a 1f [2] 21 33 [2] 0f 11 [2] 1b 0a [2] 14 10 [2] 0a 0d [2] 08 0c [2] 13 0a [2] 0f 0d [2] 13 22 }

  condition:
    any of them
}