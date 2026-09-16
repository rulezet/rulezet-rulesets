rule TTP_XOR_QUAD_CurrentVersionRun_ffc0 {
  strings:
    $key_ffc0 = { ac af [2] 88 a1 [2] a3 8d [2] 8d af [2] 99 b4 [2] 96 ae [2] 88 b3 [2] 8a b2 [2] 91 b4 [2] 8d b3 [2] 91 9c }

  condition:
    any of them
}