rule TTP_XOR_QUAD_CurrentVersionRun_466a {
  strings:
    $key_466a = { 15 05 [2] 31 0b [2] 1a 27 [2] 34 05 [2] 20 1e [2] 2f 04 [2] 31 19 [2] 33 18 [2] 28 1e [2] 34 19 [2] 28 36 }

  condition:
    any of them
}