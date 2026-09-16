rule TTP_XOR_QUAD_CurrentVersionRun_057d {
  strings:
    $key_057d = { 56 12 [2] 72 1c [2] 59 30 [2] 77 12 [2] 63 09 [2] 6c 13 [2] 72 0e [2] 70 0f [2] 6b 09 [2] 77 0e [2] 6b 21 }

  condition:
    any of them
}