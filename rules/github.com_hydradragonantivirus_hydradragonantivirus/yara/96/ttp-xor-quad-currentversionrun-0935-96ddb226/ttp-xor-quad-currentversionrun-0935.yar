rule TTP_XOR_QUAD_CurrentVersionRun_0935 {
  strings:
    $key_0935 = { 5a 5a [2] 7e 54 [2] 55 78 [2] 7b 5a [2] 6f 41 [2] 60 5b [2] 7e 46 [2] 7c 47 [2] 67 41 [2] 7b 46 [2] 67 69 }

  condition:
    any of them
}