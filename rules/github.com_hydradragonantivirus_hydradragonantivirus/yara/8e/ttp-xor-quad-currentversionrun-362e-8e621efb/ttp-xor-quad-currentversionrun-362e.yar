rule TTP_XOR_QUAD_CurrentVersionRun_362e {
  strings:
    $key_362e = { 65 41 [2] 41 4f [2] 6a 63 [2] 44 41 [2] 50 5a [2] 5f 40 [2] 41 5d [2] 43 5c [2] 58 5a [2] 44 5d [2] 58 72 }

  condition:
    any of them
}