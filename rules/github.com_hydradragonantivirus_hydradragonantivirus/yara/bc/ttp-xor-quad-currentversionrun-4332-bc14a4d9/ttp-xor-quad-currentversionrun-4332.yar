rule TTP_XOR_QUAD_CurrentVersionRun_4332 {
  strings:
    $key_4332 = { 10 5d [2] 34 53 [2] 1f 7f [2] 31 5d [2] 25 46 [2] 2a 5c [2] 34 41 [2] 36 40 [2] 2d 46 [2] 31 41 [2] 2d 6e }

  condition:
    any of them
}