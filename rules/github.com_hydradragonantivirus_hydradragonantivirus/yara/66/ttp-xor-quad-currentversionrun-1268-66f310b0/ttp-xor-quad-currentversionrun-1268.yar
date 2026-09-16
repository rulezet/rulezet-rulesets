rule TTP_XOR_QUAD_CurrentVersionRun_1268 {
  strings:
    $key_1268 = { 41 07 [2] 65 09 [2] 4e 25 [2] 60 07 [2] 74 1c [2] 7b 06 [2] 65 1b [2] 67 1a [2] 7c 1c [2] 60 1b [2] 7c 34 }

  condition:
    any of them
}