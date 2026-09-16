rule TTP_XOR_QUAD_CurrentVersionRun_051b {
  strings:
    $key_051b = { 56 74 [2] 72 7a [2] 59 56 [2] 77 74 [2] 63 6f [2] 6c 75 [2] 72 68 [2] 70 69 [2] 6b 6f [2] 77 68 [2] 6b 47 }

  condition:
    any of them
}