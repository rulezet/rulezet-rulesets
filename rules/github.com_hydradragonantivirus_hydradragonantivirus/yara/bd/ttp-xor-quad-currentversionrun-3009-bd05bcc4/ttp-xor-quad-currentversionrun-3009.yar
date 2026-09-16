rule TTP_XOR_QUAD_CurrentVersionRun_3009 {
  strings:
    $key_3009 = { 63 66 [2] 47 68 [2] 6c 44 [2] 42 66 [2] 56 7d [2] 59 67 [2] 47 7a [2] 45 7b [2] 5e 7d [2] 42 7a [2] 5e 55 }

  condition:
    any of them
}