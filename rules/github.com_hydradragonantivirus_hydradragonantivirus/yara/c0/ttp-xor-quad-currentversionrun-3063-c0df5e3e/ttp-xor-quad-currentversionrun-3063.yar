rule TTP_XOR_QUAD_CurrentVersionRun_3063 {
  strings:
    $key_3063 = { 63 0c [2] 47 02 [2] 6c 2e [2] 42 0c [2] 56 17 [2] 59 0d [2] 47 10 [2] 45 11 [2] 5e 17 [2] 42 10 [2] 5e 3f }

  condition:
    any of them
}