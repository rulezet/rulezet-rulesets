rule TTP_XOR_QUAD_CurrentVersionRun_7710 {
  strings:
    $key_7710 = { 24 7f [2] 00 71 [2] 2b 5d [2] 05 7f [2] 11 64 [2] 1e 7e [2] 00 63 [2] 02 62 [2] 19 64 [2] 05 63 [2] 19 4c }

  condition:
    any of them
}