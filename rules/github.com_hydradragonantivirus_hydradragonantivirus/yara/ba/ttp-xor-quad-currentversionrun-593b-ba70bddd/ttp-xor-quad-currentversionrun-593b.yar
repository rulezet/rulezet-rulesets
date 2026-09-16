rule TTP_XOR_QUAD_CurrentVersionRun_593b {
  strings:
    $key_593b = { 0a 54 [2] 2e 5a [2] 05 76 [2] 2b 54 [2] 3f 4f [2] 30 55 [2] 2e 48 [2] 2c 49 [2] 37 4f [2] 2b 48 [2] 37 67 }

  condition:
    any of them
}