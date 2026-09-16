rule TTP_XOR_QUAD_CurrentVersionRun_301b {
  strings:
    $key_301b = { 63 74 [2] 47 7a [2] 6c 56 [2] 42 74 [2] 56 6f [2] 59 75 [2] 47 68 [2] 45 69 [2] 5e 6f [2] 42 68 [2] 5e 47 }

  condition:
    any of them
}