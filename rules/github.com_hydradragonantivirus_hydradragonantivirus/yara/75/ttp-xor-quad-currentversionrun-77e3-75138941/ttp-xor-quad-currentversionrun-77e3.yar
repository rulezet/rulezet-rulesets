rule TTP_XOR_QUAD_CurrentVersionRun_77e3 {
  strings:
    $key_77e3 = { 24 8c [2] 00 82 [2] 2b ae [2] 05 8c [2] 11 97 [2] 1e 8d [2] 00 90 [2] 02 91 [2] 19 97 [2] 05 90 [2] 19 bf }

  condition:
    any of them
}