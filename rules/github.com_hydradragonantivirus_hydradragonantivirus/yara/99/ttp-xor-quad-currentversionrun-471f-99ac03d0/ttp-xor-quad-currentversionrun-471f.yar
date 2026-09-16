rule TTP_XOR_QUAD_CurrentVersionRun_471f {
  strings:
    $key_471f = { 14 70 [2] 30 7e [2] 1b 52 [2] 35 70 [2] 21 6b [2] 2e 71 [2] 30 6c [2] 32 6d [2] 29 6b [2] 35 6c [2] 29 43 }

  condition:
    any of them
}