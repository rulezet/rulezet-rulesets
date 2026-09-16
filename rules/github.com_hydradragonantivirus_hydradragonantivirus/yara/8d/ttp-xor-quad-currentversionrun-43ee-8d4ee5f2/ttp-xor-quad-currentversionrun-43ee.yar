rule TTP_XOR_QUAD_CurrentVersionRun_43ee {
  strings:
    $key_43ee = { 10 81 [2] 34 8f [2] 1f a3 [2] 31 81 [2] 25 9a [2] 2a 80 [2] 34 9d [2] 36 9c [2] 2d 9a [2] 31 9d [2] 2d b2 }

  condition:
    any of them
}