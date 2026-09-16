rule TTP_XOR_QUAD_CurrentVersionRun_461b {
  strings:
    $key_461b = { 15 74 [2] 31 7a [2] 1a 56 [2] 34 74 [2] 20 6f [2] 2f 75 [2] 31 68 [2] 33 69 [2] 28 6f [2] 34 68 [2] 28 47 }

  condition:
    any of them
}