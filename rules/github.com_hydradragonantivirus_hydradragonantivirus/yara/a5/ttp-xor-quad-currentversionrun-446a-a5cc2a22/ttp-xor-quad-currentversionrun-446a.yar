rule TTP_XOR_QUAD_CurrentVersionRun_446a {
  strings:
    $key_446a = { 17 05 [2] 33 0b [2] 18 27 [2] 36 05 [2] 22 1e [2] 2d 04 [2] 33 19 [2] 31 18 [2] 2a 1e [2] 36 19 [2] 2a 36 }

  condition:
    any of them
}