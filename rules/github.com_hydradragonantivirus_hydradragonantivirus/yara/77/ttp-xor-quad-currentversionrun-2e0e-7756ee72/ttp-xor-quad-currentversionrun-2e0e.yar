rule TTP_XOR_QUAD_CurrentVersionRun_2e0e {
  strings:
    $key_2e0e = { 7d 61 [2] 59 6f [2] 72 43 [2] 5c 61 [2] 48 7a [2] 47 60 [2] 59 7d [2] 5b 7c [2] 40 7a [2] 5c 7d [2] 40 52 }

  condition:
    any of them
}