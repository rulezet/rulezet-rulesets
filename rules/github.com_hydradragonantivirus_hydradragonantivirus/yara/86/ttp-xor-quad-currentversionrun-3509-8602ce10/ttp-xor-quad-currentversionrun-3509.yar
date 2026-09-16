rule TTP_XOR_QUAD_CurrentVersionRun_3509 {
  strings:
    $key_3509 = { 66 66 [2] 42 68 [2] 69 44 [2] 47 66 [2] 53 7d [2] 5c 67 [2] 42 7a [2] 40 7b [2] 5b 7d [2] 47 7a [2] 5b 55 }

  condition:
    any of them
}