rule TTP_XOR_QUAD_CurrentVersionRun_054a {
  strings:
    $key_054a = { 56 25 [2] 72 2b [2] 59 07 [2] 77 25 [2] 63 3e [2] 6c 24 [2] 72 39 [2] 70 38 [2] 6b 3e [2] 77 39 [2] 6b 16 }

  condition:
    any of them
}