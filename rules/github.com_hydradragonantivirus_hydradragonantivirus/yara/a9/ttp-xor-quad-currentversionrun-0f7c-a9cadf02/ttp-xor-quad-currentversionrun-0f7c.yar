rule TTP_XOR_QUAD_CurrentVersionRun_0f7c {
  strings:
    $key_0f7c = { 5c 13 [2] 78 1d [2] 53 31 [2] 7d 13 [2] 69 08 [2] 66 12 [2] 78 0f [2] 7a 0e [2] 61 08 [2] 7d 0f [2] 61 20 }

  condition:
    any of them
}