rule TTP_XOR_QUAD_CurrentVersionRun_43f0 {
  strings:
    $key_43f0 = { 10 9f [2] 34 91 [2] 1f bd [2] 31 9f [2] 25 84 [2] 2a 9e [2] 34 83 [2] 36 82 [2] 2d 84 [2] 31 83 [2] 2d ac }

  condition:
    any of them
}