rule TTP_XOR_QUAD_CurrentVersionRun_6b6a {
  strings:
    $key_6b6a = { 38 05 [2] 1c 0b [2] 37 27 [2] 19 05 [2] 0d 1e [2] 02 04 [2] 1c 19 [2] 1e 18 [2] 05 1e [2] 19 19 [2] 05 36 }

  condition:
    any of them
}