rule TTP_XOR_QUAD_CurrentVersionRun_1228 {
  strings:
    $key_1228 = { 41 47 [2] 65 49 [2] 4e 65 [2] 60 47 [2] 74 5c [2] 7b 46 [2] 65 5b [2] 67 5a [2] 7c 5c [2] 60 5b [2] 7c 74 }

  condition:
    any of them
}