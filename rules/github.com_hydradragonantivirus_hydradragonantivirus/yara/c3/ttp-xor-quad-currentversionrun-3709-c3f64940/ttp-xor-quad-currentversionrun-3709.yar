rule TTP_XOR_QUAD_CurrentVersionRun_3709 {
  strings:
    $key_3709 = { 64 66 [2] 40 68 [2] 6b 44 [2] 45 66 [2] 51 7d [2] 5e 67 [2] 40 7a [2] 42 7b [2] 59 7d [2] 45 7a [2] 59 55 }

  condition:
    any of them
}