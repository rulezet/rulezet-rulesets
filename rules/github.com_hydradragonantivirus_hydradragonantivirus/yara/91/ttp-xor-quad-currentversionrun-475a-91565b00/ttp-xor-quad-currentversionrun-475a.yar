rule TTP_XOR_QUAD_CurrentVersionRun_475a {
  strings:
    $key_475a = { 14 35 [2] 30 3b [2] 1b 17 [2] 35 35 [2] 21 2e [2] 2e 34 [2] 30 29 [2] 32 28 [2] 29 2e [2] 35 29 [2] 29 06 }

  condition:
    any of them
}