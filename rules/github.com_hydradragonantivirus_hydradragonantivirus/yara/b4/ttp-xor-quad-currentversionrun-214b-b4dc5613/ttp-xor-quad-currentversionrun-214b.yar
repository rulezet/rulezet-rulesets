rule TTP_XOR_QUAD_CurrentVersionRun_214b {
  strings:
    $key_214b = { 72 24 [2] 56 2a [2] 7d 06 [2] 53 24 [2] 47 3f [2] 48 25 [2] 56 38 [2] 54 39 [2] 4f 3f [2] 53 38 [2] 4f 17 }

  condition:
    any of them
}