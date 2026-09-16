rule TTP_XOR_QUAD_CurrentVersionRun_6721 {
  strings:
    $key_6721 = { 34 4e [2] 10 40 [2] 3b 6c [2] 15 4e [2] 01 55 [2] 0e 4f [2] 10 52 [2] 12 53 [2] 09 55 [2] 15 52 [2] 09 7d }

  condition:
    any of them
}