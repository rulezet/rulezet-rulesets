rule TTP_XOR_QUAD_CurrentVersionRun_f3c1 {
  strings:
    $key_f3c1 = { a0 ae [2] 84 a0 [2] af 8c [2] 81 ae [2] 95 b5 [2] 9a af [2] 84 b2 [2] 86 b3 [2] 9d b5 [2] 81 b2 [2] 9d 9d }

  condition:
    any of them
}