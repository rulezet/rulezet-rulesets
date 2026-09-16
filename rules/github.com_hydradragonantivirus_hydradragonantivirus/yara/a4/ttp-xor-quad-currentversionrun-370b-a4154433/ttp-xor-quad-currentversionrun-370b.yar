rule TTP_XOR_QUAD_CurrentVersionRun_370b {
  strings:
    $key_370b = { 64 64 [2] 40 6a [2] 6b 46 [2] 45 64 [2] 51 7f [2] 5e 65 [2] 40 78 [2] 42 79 [2] 59 7f [2] 45 78 [2] 59 57 }

  condition:
    any of them
}