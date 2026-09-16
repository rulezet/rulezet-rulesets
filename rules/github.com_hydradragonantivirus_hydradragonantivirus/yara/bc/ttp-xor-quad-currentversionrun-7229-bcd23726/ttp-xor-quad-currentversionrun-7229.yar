rule TTP_XOR_QUAD_CurrentVersionRun_7229 {
  strings:
    $key_7229 = { 21 46 [2] 05 48 [2] 2e 64 [2] 00 46 [2] 14 5d [2] 1b 47 [2] 05 5a [2] 07 5b [2] 1c 5d [2] 00 5a [2] 1c 75 }

  condition:
    any of them
}