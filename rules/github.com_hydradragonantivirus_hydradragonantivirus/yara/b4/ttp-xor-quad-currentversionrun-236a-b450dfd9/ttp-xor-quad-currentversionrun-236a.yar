rule TTP_XOR_QUAD_CurrentVersionRun_236a {
  strings:
    $key_236a = { 70 05 [2] 54 0b [2] 7f 27 [2] 51 05 [2] 45 1e [2] 4a 04 [2] 54 19 [2] 56 18 [2] 4d 1e [2] 51 19 [2] 4d 36 }

  condition:
    any of them
}