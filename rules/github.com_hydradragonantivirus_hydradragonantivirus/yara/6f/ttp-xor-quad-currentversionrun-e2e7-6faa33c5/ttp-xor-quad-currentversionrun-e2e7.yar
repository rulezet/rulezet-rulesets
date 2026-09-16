rule TTP_XOR_QUAD_CurrentVersionRun_e2e7 {
  strings:
    $key_e2e7 = { b1 88 [2] 95 86 [2] be aa [2] 90 88 [2] 84 93 [2] 8b 89 [2] 95 94 [2] 97 95 [2] 8c 93 [2] 90 94 [2] 8c bb }

  condition:
    any of them
}