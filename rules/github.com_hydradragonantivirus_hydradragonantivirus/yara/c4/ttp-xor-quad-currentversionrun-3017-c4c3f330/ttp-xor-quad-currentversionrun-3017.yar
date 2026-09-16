rule TTP_XOR_QUAD_CurrentVersionRun_3017 {
  strings:
    $key_3017 = { 63 78 [2] 47 76 [2] 6c 5a [2] 42 78 [2] 56 63 [2] 59 79 [2] 47 64 [2] 45 65 [2] 5e 63 [2] 42 64 [2] 5e 4b }

  condition:
    any of them
}