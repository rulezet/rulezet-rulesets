rule TTP_XOR_QUAD_CurrentVersionRun_057c {
  strings:
    $key_057c = { 56 13 [2] 72 1d [2] 59 31 [2] 77 13 [2] 63 08 [2] 6c 12 [2] 72 0f [2] 70 0e [2] 6b 08 [2] 77 0f [2] 6b 20 }

  condition:
    any of them
}