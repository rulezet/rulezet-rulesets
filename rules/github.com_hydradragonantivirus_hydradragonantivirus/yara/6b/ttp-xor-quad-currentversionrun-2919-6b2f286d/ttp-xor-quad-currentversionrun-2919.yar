rule TTP_XOR_QUAD_CurrentVersionRun_2919 {
  strings:
    $key_2919 = { 7a 76 [2] 5e 78 [2] 75 54 [2] 5b 76 [2] 4f 6d [2] 40 77 [2] 5e 6a [2] 5c 6b [2] 47 6d [2] 5b 6a [2] 47 45 }

  condition:
    any of them
}