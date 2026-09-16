rule TTP_XOR_QUAD_CurrentVersionRun_2c0e {
  strings:
    $key_2c0e = { 7f 61 [2] 5b 6f [2] 70 43 [2] 5e 61 [2] 4a 7a [2] 45 60 [2] 5b 7d [2] 59 7c [2] 42 7a [2] 5e 7d [2] 42 52 }

  condition:
    any of them
}