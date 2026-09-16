rule TTP_XOR_QUAD_CurrentVersionRun_653e {
  strings:
    $key_653e = { 36 51 [2] 12 5f [2] 39 73 [2] 17 51 [2] 03 4a [2] 0c 50 [2] 12 4d [2] 10 4c [2] 0b 4a [2] 17 4d [2] 0b 62 }

  condition:
    any of them
}