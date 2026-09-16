rule TTP_XOR_QUAD_CurrentVersionRun_3c28 {
  strings:
    $key_3c28 = { 6f 47 [2] 4b 49 [2] 60 65 [2] 4e 47 [2] 5a 5c [2] 55 46 [2] 4b 5b [2] 49 5a [2] 52 5c [2] 4e 5b [2] 52 74 }

  condition:
    any of them
}