rule TTP_XOR_QUAD_CurrentVersionRun_592e {
  strings:
    $key_592e = { 0a 41 [2] 2e 4f [2] 05 63 [2] 2b 41 [2] 3f 5a [2] 30 40 [2] 2e 5d [2] 2c 5c [2] 37 5a [2] 2b 5d [2] 37 72 }

  condition:
    any of them
}