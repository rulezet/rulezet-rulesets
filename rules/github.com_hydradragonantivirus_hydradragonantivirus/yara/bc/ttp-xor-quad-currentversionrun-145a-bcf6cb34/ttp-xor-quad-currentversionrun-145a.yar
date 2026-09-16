rule TTP_XOR_QUAD_CurrentVersionRun_145a {
  strings:
    $key_145a = { 47 35 [2] 63 3b [2] 48 17 [2] 66 35 [2] 72 2e [2] 7d 34 [2] 63 29 [2] 61 28 [2] 7a 2e [2] 66 29 [2] 7a 06 }

  condition:
    any of them
}