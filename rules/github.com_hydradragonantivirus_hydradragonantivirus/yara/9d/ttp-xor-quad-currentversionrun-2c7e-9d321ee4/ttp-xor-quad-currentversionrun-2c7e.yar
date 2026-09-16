rule TTP_XOR_QUAD_CurrentVersionRun_2c7e {
  strings:
    $key_2c7e = { 7f 11 [2] 5b 1f [2] 70 33 [2] 5e 11 [2] 4a 0a [2] 45 10 [2] 5b 0d [2] 59 0c [2] 42 0a [2] 5e 0d [2] 42 22 }

  condition:
    any of them
}