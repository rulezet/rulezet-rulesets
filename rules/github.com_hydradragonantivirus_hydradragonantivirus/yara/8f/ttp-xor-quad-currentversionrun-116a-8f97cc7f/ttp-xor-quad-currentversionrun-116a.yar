rule TTP_XOR_QUAD_CurrentVersionRun_116a {
  strings:
    $key_116a = { 42 05 [2] 66 0b [2] 4d 27 [2] 63 05 [2] 77 1e [2] 78 04 [2] 66 19 [2] 64 18 [2] 7f 1e [2] 63 19 [2] 7f 36 }

  condition:
    any of them
}