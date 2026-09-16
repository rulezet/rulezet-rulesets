rule TTP_XOR_QUAD_CurrentVersionRun_2e09 {
  strings:
    $key_2e09 = { 7d 66 [2] 59 68 [2] 72 44 [2] 5c 66 [2] 48 7d [2] 47 67 [2] 59 7a [2] 5b 7b [2] 40 7d [2] 5c 7a [2] 40 55 }

  condition:
    any of them
}