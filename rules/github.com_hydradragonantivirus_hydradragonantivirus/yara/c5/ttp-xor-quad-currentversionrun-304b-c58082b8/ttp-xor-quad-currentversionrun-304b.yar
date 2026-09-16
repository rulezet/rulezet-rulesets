rule TTP_XOR_QUAD_CurrentVersionRun_304b {
  strings:
    $key_304b = { 63 24 [2] 47 2a [2] 6c 06 [2] 42 24 [2] 56 3f [2] 59 25 [2] 47 38 [2] 45 39 [2] 5e 3f [2] 42 38 [2] 5e 17 }

  condition:
    any of them
}