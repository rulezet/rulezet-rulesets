rule TTP_XOR_QUAD_CurrentVersionRun_5709 {
  strings:
    $key_5709 = { 04 66 [2] 20 68 [2] 0b 44 [2] 25 66 [2] 31 7d [2] 3e 67 [2] 20 7a [2] 22 7b [2] 39 7d [2] 25 7a [2] 39 55 }

  condition:
    any of them
}