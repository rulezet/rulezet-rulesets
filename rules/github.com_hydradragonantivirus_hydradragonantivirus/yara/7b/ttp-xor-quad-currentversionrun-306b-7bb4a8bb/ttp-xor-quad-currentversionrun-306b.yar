rule TTP_XOR_QUAD_CurrentVersionRun_306b {
  strings:
    $key_306b = { 63 04 [2] 47 0a [2] 6c 26 [2] 42 04 [2] 56 1f [2] 59 05 [2] 47 18 [2] 45 19 [2] 5e 1f [2] 42 18 [2] 5e 37 }

  condition:
    any of them
}