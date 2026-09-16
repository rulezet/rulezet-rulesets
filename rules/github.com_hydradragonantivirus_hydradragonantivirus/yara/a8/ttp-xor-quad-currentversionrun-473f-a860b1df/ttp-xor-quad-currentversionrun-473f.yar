rule TTP_XOR_QUAD_CurrentVersionRun_473f {
  strings:
    $key_473f = { 14 50 [2] 30 5e [2] 1b 72 [2] 35 50 [2] 21 4b [2] 2e 51 [2] 30 4c [2] 32 4d [2] 29 4b [2] 35 4c [2] 29 63 }

  condition:
    any of them
}