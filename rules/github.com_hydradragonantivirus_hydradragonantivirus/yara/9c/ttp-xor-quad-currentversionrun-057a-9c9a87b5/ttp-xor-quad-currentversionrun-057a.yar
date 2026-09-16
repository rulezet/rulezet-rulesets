rule TTP_XOR_QUAD_CurrentVersionRun_057a {
  strings:
    $key_057a = { 56 15 [2] 72 1b [2] 59 37 [2] 77 15 [2] 63 0e [2] 6c 14 [2] 72 09 [2] 70 08 [2] 6b 0e [2] 77 09 [2] 6b 26 }

  condition:
    any of them
}