rule TTP_XOR_QUAD_CurrentVersionRun_0d27 {
  strings:
    $key_0d27 = { 5e 48 [2] 7a 46 [2] 51 6a [2] 7f 48 [2] 6b 53 [2] 64 49 [2] 7a 54 [2] 78 55 [2] 63 53 [2] 7f 54 [2] 63 7b }

  condition:
    any of them
}