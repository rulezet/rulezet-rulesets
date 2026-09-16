rule TTP_XOR_QUAD_CurrentVersionRun_3c35 {
  strings:
    $key_3c35 = { 6f 5a [2] 4b 54 [2] 60 78 [2] 4e 5a [2] 5a 41 [2] 55 5b [2] 4b 46 [2] 49 47 [2] 52 41 [2] 4e 46 [2] 52 69 }

  condition:
    any of them
}