rule TTP_XOR_QUAD_CurrentVersionRun_3519 {
  strings:
    $key_3519 = { 66 76 [2] 42 78 [2] 69 54 [2] 47 76 [2] 53 6d [2] 5c 77 [2] 42 6a [2] 40 6b [2] 5b 6d [2] 47 6a [2] 5b 45 }

  condition:
    any of them
}