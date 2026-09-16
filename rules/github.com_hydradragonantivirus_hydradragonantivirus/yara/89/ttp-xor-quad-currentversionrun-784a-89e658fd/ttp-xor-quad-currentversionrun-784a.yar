rule TTP_XOR_QUAD_CurrentVersionRun_784a {
  strings:
    $key_784a = { 2b 25 [2] 0f 2b [2] 24 07 [2] 0a 25 [2] 1e 3e [2] 11 24 [2] 0f 39 [2] 0d 38 [2] 16 3e [2] 0a 39 [2] 16 16 }

  condition:
    any of them
}