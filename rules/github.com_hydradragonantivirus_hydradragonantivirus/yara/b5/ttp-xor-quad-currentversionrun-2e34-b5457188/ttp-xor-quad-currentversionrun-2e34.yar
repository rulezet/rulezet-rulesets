rule TTP_XOR_QUAD_CurrentVersionRun_2e34 {
  strings:
    $key_2e34 = { 7d 5b [2] 59 55 [2] 72 79 [2] 5c 5b [2] 48 40 [2] 47 5a [2] 59 47 [2] 5b 46 [2] 40 40 [2] 5c 47 [2] 40 68 }

  condition:
    any of them
}