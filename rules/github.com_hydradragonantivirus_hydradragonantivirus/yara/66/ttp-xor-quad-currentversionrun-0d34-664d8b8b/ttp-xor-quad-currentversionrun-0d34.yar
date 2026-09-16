rule TTP_XOR_QUAD_CurrentVersionRun_0d34 {
  strings:
    $key_0d34 = { 5e 5b [2] 7a 55 [2] 51 79 [2] 7f 5b [2] 6b 40 [2] 64 5a [2] 7a 47 [2] 78 46 [2] 63 40 [2] 7f 47 [2] 63 68 }

  condition:
    any of them
}