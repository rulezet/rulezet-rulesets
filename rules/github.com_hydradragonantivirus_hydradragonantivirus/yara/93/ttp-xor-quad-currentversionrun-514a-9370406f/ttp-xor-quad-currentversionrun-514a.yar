rule TTP_XOR_QUAD_CurrentVersionRun_514a {
  strings:
    $key_514a = { 02 25 [2] 26 2b [2] 0d 07 [2] 23 25 [2] 37 3e [2] 38 24 [2] 26 39 [2] 24 38 [2] 3f 3e [2] 23 39 [2] 3f 16 }

  condition:
    any of them
}