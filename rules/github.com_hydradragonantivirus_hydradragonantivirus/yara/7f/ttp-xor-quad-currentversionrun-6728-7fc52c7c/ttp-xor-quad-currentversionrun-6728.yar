rule TTP_XOR_QUAD_CurrentVersionRun_6728 {
  strings:
    $key_6728 = { 34 47 [2] 10 49 [2] 3b 65 [2] 15 47 [2] 01 5c [2] 0e 46 [2] 10 5b [2] 12 5a [2] 09 5c [2] 15 5b [2] 09 74 }

  condition:
    any of them
}