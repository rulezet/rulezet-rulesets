rule TTP_XOR_QUAD_CurrentVersionRun_371b {
  strings:
    $key_371b = { 64 74 [2] 40 7a [2] 6b 56 [2] 45 74 [2] 51 6f [2] 5e 75 [2] 40 68 [2] 42 69 [2] 59 6f [2] 45 68 [2] 59 47 }

  condition:
    any of them
}