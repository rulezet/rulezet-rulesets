rule TTP_XOR_QUAD_CurrentVersionRun_1934 {
  strings:
    $key_1934 = { 4a 5b [2] 6e 55 [2] 45 79 [2] 6b 5b [2] 7f 40 [2] 70 5a [2] 6e 47 [2] 6c 46 [2] 77 40 [2] 6b 47 [2] 77 68 }

  condition:
    any of them
}