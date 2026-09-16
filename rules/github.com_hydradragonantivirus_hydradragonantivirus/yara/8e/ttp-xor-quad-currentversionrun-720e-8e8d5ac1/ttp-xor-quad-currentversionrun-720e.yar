rule TTP_XOR_QUAD_CurrentVersionRun_720e {
  strings:
    $key_720e = { 21 61 [2] 05 6f [2] 2e 43 [2] 00 61 [2] 14 7a [2] 1b 60 [2] 05 7d [2] 07 7c [2] 1c 7a [2] 00 7d [2] 1c 52 }

  condition:
    any of them
}