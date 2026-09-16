rule TTP_XOR_QUAD_CurrentVersionRun_76e3 {
  strings:
    $key_76e3 = { 25 8c [2] 01 82 [2] 2a ae [2] 04 8c [2] 10 97 [2] 1f 8d [2] 01 90 [2] 03 91 [2] 18 97 [2] 04 90 [2] 18 bf }

  condition:
    any of them
}