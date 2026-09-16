rule TTP_XOR_QUAD_CurrentVersionRun_f7c1 {
  strings:
    $key_f7c1 = { a4 ae [2] 80 a0 [2] ab 8c [2] 85 ae [2] 91 b5 [2] 9e af [2] 80 b2 [2] 82 b3 [2] 99 b5 [2] 85 b2 [2] 99 9d }

  condition:
    any of them
}