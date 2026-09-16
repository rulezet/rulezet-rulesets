rule TTP_XOR_QUAD_CurrentVersionRun_147c {
  strings:
    $key_147c = { 47 13 [2] 63 1d [2] 48 31 [2] 66 13 [2] 72 08 [2] 7d 12 [2] 63 0f [2] 61 0e [2] 7a 08 [2] 66 0f [2] 7a 20 }

  condition:
    any of them
}