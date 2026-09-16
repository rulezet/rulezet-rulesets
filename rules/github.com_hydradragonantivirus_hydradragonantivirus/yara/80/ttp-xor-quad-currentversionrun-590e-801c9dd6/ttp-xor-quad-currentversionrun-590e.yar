rule TTP_XOR_QUAD_CurrentVersionRun_590e {
  strings:
    $key_590e = { 0a 61 [2] 2e 6f [2] 05 43 [2] 2b 61 [2] 3f 7a [2] 30 60 [2] 2e 7d [2] 2c 7c [2] 37 7a [2] 2b 7d [2] 37 52 }

  condition:
    any of them
}