rule TTP_XOR_QUAD_CurrentVersionRun_00e7 {
  strings:
    $key_00e7 = { 53 88 [2] 77 86 [2] 5c aa [2] 72 88 [2] 66 93 [2] 69 89 [2] 77 94 [2] 75 95 [2] 6e 93 [2] 72 94 [2] 6e bb }

  condition:
    any of them
}