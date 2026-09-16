rule TTP_XOR_QUAD_CurrentVersionRun_4929 {
  strings:
    $key_4929 = { 1a 46 [2] 3e 48 [2] 15 64 [2] 3b 46 [2] 2f 5d [2] 20 47 [2] 3e 5a [2] 3c 5b [2] 27 5d [2] 3b 5a [2] 27 75 }

  condition:
    any of them
}