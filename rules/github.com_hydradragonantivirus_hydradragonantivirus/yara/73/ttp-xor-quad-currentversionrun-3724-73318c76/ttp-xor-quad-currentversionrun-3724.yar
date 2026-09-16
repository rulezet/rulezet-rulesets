rule TTP_XOR_QUAD_CurrentVersionRun_3724 {
  strings:
    $key_3724 = { 64 4b [2] 40 45 [2] 6b 69 [2] 45 4b [2] 51 50 [2] 5e 4a [2] 40 57 [2] 42 56 [2] 59 50 [2] 45 57 [2] 59 78 }

  condition:
    any of them
}