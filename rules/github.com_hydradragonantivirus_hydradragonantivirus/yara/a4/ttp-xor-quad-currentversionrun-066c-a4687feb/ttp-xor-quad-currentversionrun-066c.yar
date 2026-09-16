rule TTP_XOR_QUAD_CurrentVersionRun_066c {
  strings:
    $key_066c = { 55 03 [2] 71 0d [2] 5a 21 [2] 74 03 [2] 60 18 [2] 6f 02 [2] 71 1f [2] 73 1e [2] 68 18 [2] 74 1f [2] 68 30 }

  condition:
    any of them
}