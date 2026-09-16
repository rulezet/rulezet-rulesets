rule TTP_XOR_QUAD_CurrentVersionRun_0d29 {
  strings:
    $key_0d29 = { 5e 46 [2] 7a 48 [2] 51 64 [2] 7f 46 [2] 6b 5d [2] 64 47 [2] 7a 5a [2] 78 5b [2] 63 5d [2] 7f 5a [2] 63 75 }

  condition:
    any of them
}