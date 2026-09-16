rule TTP_XOR_QUAD_CurrentVersionRun_7721 {
  strings:
    $key_7721 = { 24 4e [2] 00 40 [2] 2b 6c [2] 05 4e [2] 11 55 [2] 1e 4f [2] 00 52 [2] 02 53 [2] 19 55 [2] 05 52 [2] 19 7d }

  condition:
    any of them
}