rule TTP_XOR_QUAD_CurrentVersionRun_593e {
  strings:
    $key_593e = { 0a 51 [2] 2e 5f [2] 05 73 [2] 2b 51 [2] 3f 4a [2] 30 50 [2] 2e 4d [2] 2c 4c [2] 37 4a [2] 2b 4d [2] 37 62 }

  condition:
    any of them
}