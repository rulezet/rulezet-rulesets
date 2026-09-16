rule TTP_XOR_QUAD_CurrentVersionRun_1728 {
  strings:
    $key_1728 = { 44 47 [2] 60 49 [2] 4b 65 [2] 65 47 [2] 71 5c [2] 7e 46 [2] 60 5b [2] 62 5a [2] 79 5c [2] 65 5b [2] 79 74 }

  condition:
    any of them
}