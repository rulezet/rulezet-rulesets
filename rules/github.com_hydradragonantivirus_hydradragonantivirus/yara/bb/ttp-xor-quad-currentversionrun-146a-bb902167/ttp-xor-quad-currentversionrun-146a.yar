rule TTP_XOR_QUAD_CurrentVersionRun_146a {
  strings:
    $key_146a = { 47 05 [2] 63 0b [2] 48 27 [2] 66 05 [2] 72 1e [2] 7d 04 [2] 63 19 [2] 61 18 [2] 7a 1e [2] 66 19 [2] 7a 36 }

  condition:
    any of them
}