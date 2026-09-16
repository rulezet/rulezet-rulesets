rule TTP_XOR_QUAD_CurrentVersionRun_277f {
  strings:
    $key_277f = { 74 10 [2] 50 1e [2] 7b 32 [2] 55 10 [2] 41 0b [2] 4e 11 [2] 50 0c [2] 52 0d [2] 49 0b [2] 55 0c [2] 49 23 }

  condition:
    any of them
}