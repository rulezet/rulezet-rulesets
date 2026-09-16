rule TTP_XOR_QUAD_CurrentVersionRun_7d11 {
  strings:
    $key_7d11 = { 2e 7e [2] 0a 70 [2] 21 5c [2] 0f 7e [2] 1b 65 [2] 14 7f [2] 0a 62 [2] 08 63 [2] 13 65 [2] 0f 62 [2] 13 4d }

  condition:
    any of them
}