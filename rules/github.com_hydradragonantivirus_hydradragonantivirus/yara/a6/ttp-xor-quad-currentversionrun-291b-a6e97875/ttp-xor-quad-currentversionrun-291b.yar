rule TTP_XOR_QUAD_CurrentVersionRun_291b {
  strings:
    $key_291b = { 7a 74 [2] 5e 7a [2] 75 56 [2] 5b 74 [2] 4f 6f [2] 40 75 [2] 5e 68 [2] 5c 69 [2] 47 6f [2] 5b 68 [2] 47 47 }

  condition:
    any of them
}