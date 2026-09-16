rule TTP_XOR_QUAD_CurrentVersionRun_2829 {
  strings:
    $key_2829 = { 7b 46 [2] 5f 48 [2] 74 64 [2] 5a 46 [2] 4e 5d [2] 41 47 [2] 5f 5a [2] 5d 5b [2] 46 5d [2] 5a 5a [2] 46 75 }

  condition:
    any of them
}