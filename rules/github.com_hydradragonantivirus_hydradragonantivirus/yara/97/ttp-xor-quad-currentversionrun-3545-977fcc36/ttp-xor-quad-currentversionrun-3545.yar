rule TTP_XOR_QUAD_CurrentVersionRun_3545 {
  strings:
    $key_3545 = { 66 2a [2] 42 24 [2] 69 08 [2] 47 2a [2] 53 31 [2] 5c 2b [2] 42 36 [2] 40 37 [2] 5b 31 [2] 47 36 [2] 5b 19 }

  condition:
    any of them
}