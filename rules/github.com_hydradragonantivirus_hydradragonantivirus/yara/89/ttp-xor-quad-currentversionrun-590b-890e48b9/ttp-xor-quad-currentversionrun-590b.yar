rule TTP_XOR_QUAD_CurrentVersionRun_590b {
  strings:
    $key_590b = { 0a 64 [2] 2e 6a [2] 05 46 [2] 2b 64 [2] 3f 7f [2] 30 65 [2] 2e 78 [2] 2c 79 [2] 37 7f [2] 2b 78 [2] 37 57 }

  condition:
    any of them
}