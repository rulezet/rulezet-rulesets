rule TTP_XOR_QUAD_CurrentVersionRun_6b7a {
  strings:
    $key_6b7a = { 38 15 [2] 1c 1b [2] 37 37 [2] 19 15 [2] 0d 0e [2] 02 14 [2] 1c 09 [2] 1e 08 [2] 05 0e [2] 19 09 [2] 05 26 }

  condition:
    any of them
}