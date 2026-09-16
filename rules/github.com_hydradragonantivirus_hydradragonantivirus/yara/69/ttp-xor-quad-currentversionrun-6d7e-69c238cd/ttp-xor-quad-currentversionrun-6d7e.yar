rule TTP_XOR_QUAD_CurrentVersionRun_6d7e {
  strings:
    $key_6d7e = { 3e 11 [2] 1a 1f [2] 31 33 [2] 1f 11 [2] 0b 0a [2] 04 10 [2] 1a 0d [2] 18 0c [2] 03 0a [2] 1f 0d [2] 03 22 }

  condition:
    any of them
}