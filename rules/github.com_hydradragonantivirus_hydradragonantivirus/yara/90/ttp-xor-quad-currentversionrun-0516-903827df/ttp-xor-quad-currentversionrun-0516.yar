rule TTP_XOR_QUAD_CurrentVersionRun_0516 {
  strings:
    $key_0516 = { 56 79 [2] 72 77 [2] 59 5b [2] 77 79 [2] 63 62 [2] 6c 78 [2] 72 65 [2] 70 64 [2] 6b 62 [2] 77 65 [2] 6b 4a }

  condition:
    any of them
}