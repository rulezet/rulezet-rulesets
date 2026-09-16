rule TTP_XOR_QUAD_CurrentVersionRun_324b {
  strings:
    $key_324b = { 61 24 [2] 45 2a [2] 6e 06 [2] 40 24 [2] 54 3f [2] 5b 25 [2] 45 38 [2] 47 39 [2] 5c 3f [2] 40 38 [2] 5c 17 }

  condition:
    any of them
}