rule TTP_XOR_QUAD_CurrentVersionRun_0929 {
  strings:
    $key_0929 = { 5a 46 [2] 7e 48 [2] 55 64 [2] 7b 46 [2] 6f 5d [2] 60 47 [2] 7e 5a [2] 7c 5b [2] 67 5d [2] 7b 5a [2] 67 75 }

  condition:
    any of them
}