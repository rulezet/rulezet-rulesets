rule TTP_XOR_QUAD_CurrentVersionRun_2f2e {
  strings:
    $key_2f2e = { 7c 41 [2] 58 4f [2] 73 63 [2] 5d 41 [2] 49 5a [2] 46 40 [2] 58 5d [2] 5a 5c [2] 41 5a [2] 5d 5d [2] 41 72 }

  condition:
    any of them
}