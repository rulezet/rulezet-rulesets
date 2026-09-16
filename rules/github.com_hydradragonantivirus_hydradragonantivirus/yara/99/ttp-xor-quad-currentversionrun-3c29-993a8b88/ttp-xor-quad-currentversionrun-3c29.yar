rule TTP_XOR_QUAD_CurrentVersionRun_3c29 {
  strings:
    $key_3c29 = { 6f 46 [2] 4b 48 [2] 60 64 [2] 4e 46 [2] 5a 5d [2] 55 47 [2] 4b 5a [2] 49 5b [2] 52 5d [2] 4e 5a [2] 52 75 }

  condition:
    any of them
}