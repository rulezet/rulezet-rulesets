rule TTP_XOR_QUAD_CurrentVersionRun_50e7 {
  strings:
    $key_50e7 = { 03 88 [2] 27 86 [2] 0c aa [2] 22 88 [2] 36 93 [2] 39 89 [2] 27 94 [2] 25 95 [2] 3e 93 [2] 22 94 [2] 3e bb }

  condition:
    any of them
}