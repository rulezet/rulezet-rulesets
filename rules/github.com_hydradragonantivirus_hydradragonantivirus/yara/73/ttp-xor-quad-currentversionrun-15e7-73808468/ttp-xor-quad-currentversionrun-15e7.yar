rule TTP_XOR_QUAD_CurrentVersionRun_15e7 {
  strings:
    $key_15e7 = { 46 88 [2] 62 86 [2] 49 aa [2] 67 88 [2] 73 93 [2] 7c 89 [2] 62 94 [2] 60 95 [2] 7b 93 [2] 67 94 [2] 7b bb }

  condition:
    any of them
}