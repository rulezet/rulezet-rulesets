rule TTP_XOR_QUAD_CurrentVersionRun_490e {
  strings:
    $key_490e = { 1a 61 [2] 3e 6f [2] 15 43 [2] 3b 61 [2] 2f 7a [2] 20 60 [2] 3e 7d [2] 3c 7c [2] 27 7a [2] 3b 7d [2] 27 52 }

  condition:
    any of them
}