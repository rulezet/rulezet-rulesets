rule TTP_XOR_QUAD_CurrentVersionRun_463f {
  strings:
    $key_463f = { 15 50 [2] 31 5e [2] 1a 72 [2] 34 50 [2] 20 4b [2] 2f 51 [2] 31 4c [2] 33 4d [2] 28 4b [2] 34 4c [2] 28 63 }

  condition:
    any of them
}