rule TTP_XOR_QUAD_CurrentVersionRun_767e {
  strings:
    $key_767e = { 25 11 [2] 01 1f [2] 2a 33 [2] 04 11 [2] 10 0a [2] 1f 10 [2] 01 0d [2] 03 0c [2] 18 0a [2] 04 0d [2] 18 22 }

  condition:
    any of them
}