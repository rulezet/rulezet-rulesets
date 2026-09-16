rule TTP_XOR_QUAD_CurrentVersionRun_3b34 {
  strings:
    $key_3b34 = { 68 5b [2] 4c 55 [2] 67 79 [2] 49 5b [2] 5d 40 [2] 52 5a [2] 4c 47 [2] 4e 46 [2] 55 40 [2] 49 47 [2] 55 68 }

  condition:
    any of them
}