rule TTP_XOR_QUAD_CurrentVersionRun_2e03 {
  strings:
    $key_2e03 = { 7d 6c [2] 59 62 [2] 72 4e [2] 5c 6c [2] 48 77 [2] 47 6d [2] 59 70 [2] 5b 71 [2] 40 77 [2] 5c 70 [2] 40 5f }

  condition:
    any of them
}