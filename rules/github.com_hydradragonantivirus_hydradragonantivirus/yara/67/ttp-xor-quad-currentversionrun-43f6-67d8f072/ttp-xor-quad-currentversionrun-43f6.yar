rule TTP_XOR_QUAD_CurrentVersionRun_43f6 {
  strings:
    $key_43f6 = { 10 99 [2] 34 97 [2] 1f bb [2] 31 99 [2] 25 82 [2] 2a 98 [2] 34 85 [2] 36 84 [2] 2d 82 [2] 31 85 [2] 2d aa }

  condition:
    any of them
}