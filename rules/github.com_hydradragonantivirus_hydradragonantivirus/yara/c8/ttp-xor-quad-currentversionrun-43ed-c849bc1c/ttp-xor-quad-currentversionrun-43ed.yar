rule TTP_XOR_QUAD_CurrentVersionRun_43ed {
  strings:
    $key_43ed = { 10 82 [2] 34 8c [2] 1f a0 [2] 31 82 [2] 25 99 [2] 2a 83 [2] 34 9e [2] 36 9f [2] 2d 99 [2] 31 9e [2] 2d b1 }

  condition:
    any of them
}