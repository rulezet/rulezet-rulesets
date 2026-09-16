rule TTP_XOR_QUAD_CurrentVersionRun_3a6a {
  strings:
    $key_3a6a = { 69 05 [2] 4d 0b [2] 66 27 [2] 48 05 [2] 5c 1e [2] 53 04 [2] 4d 19 [2] 4f 18 [2] 54 1e [2] 48 19 [2] 54 36 }

  condition:
    any of them
}