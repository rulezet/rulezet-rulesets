rule TTP_XOR_QUAD_CurrentVersionRun_2e11 {
  strings:
    $key_2e11 = { 7d 7e [2] 59 70 [2] 72 5c [2] 5c 7e [2] 48 65 [2] 47 7f [2] 59 62 [2] 5b 63 [2] 40 65 [2] 5c 62 [2] 40 4d }

  condition:
    any of them
}