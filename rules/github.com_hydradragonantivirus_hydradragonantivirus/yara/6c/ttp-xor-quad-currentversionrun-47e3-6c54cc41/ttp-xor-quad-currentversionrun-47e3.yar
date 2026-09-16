rule TTP_XOR_QUAD_CurrentVersionRun_47e3 {
  strings:
    $key_47e3 = { 14 8c [2] 30 82 [2] 1b ae [2] 35 8c [2] 21 97 [2] 2e 8d [2] 30 90 [2] 32 91 [2] 29 97 [2] 35 90 [2] 29 bf }

  condition:
    any of them
}