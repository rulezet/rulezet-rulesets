rule TTP_XOR_QUAD_CurrentVersionRun_346a {
  strings:
    $key_346a = { 67 05 [2] 43 0b [2] 68 27 [2] 46 05 [2] 52 1e [2] 5d 04 [2] 43 19 [2] 41 18 [2] 5a 1e [2] 46 19 [2] 5a 36 }

  condition:
    any of them
}