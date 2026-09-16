rule TTP_XOR_QUAD_CurrentVersionRun_1828 {
  strings:
    $key_1828 = { 4b 47 [2] 6f 49 [2] 44 65 [2] 6a 47 [2] 7e 5c [2] 71 46 [2] 6f 5b [2] 6d 5a [2] 76 5c [2] 6a 5b [2] 76 74 }

  condition:
    any of them
}