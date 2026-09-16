rule TTP_XOR_QUAD_CurrentVersionRun_4021 {
  strings:
    $key_4021 = { 13 4e [2] 37 40 [2] 1c 6c [2] 32 4e [2] 26 55 [2] 29 4f [2] 37 52 [2] 35 53 [2] 2e 55 [2] 32 52 [2] 2e 7d }

  condition:
    any of them
}