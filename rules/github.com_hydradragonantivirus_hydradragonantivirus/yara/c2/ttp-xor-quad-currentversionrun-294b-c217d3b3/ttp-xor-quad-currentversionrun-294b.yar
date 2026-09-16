rule TTP_XOR_QUAD_CurrentVersionRun_294b {
  strings:
    $key_294b = { 7a 24 [2] 5e 2a [2] 75 06 [2] 5b 24 [2] 4f 3f [2] 40 25 [2] 5e 38 [2] 5c 39 [2] 47 3f [2] 5b 38 [2] 47 17 }

  condition:
    any of them
}