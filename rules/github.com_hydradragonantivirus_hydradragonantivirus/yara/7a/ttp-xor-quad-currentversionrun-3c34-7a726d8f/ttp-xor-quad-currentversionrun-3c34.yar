rule TTP_XOR_QUAD_CurrentVersionRun_3c34 {
  strings:
    $key_3c34 = { 6f 5b [2] 4b 55 [2] 60 79 [2] 4e 5b [2] 5a 40 [2] 55 5a [2] 4b 47 [2] 49 46 [2] 52 40 [2] 4e 47 [2] 52 68 }

  condition:
    any of them
}