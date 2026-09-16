rule TTP_XOR_QUAD_CurrentVersionRun_0934 {
  strings:
    $key_0934 = { 5a 5b [2] 7e 55 [2] 55 79 [2] 7b 5b [2] 6f 40 [2] 60 5a [2] 7e 47 [2] 7c 46 [2] 67 40 [2] 7b 47 [2] 67 68 }

  condition:
    any of them
}