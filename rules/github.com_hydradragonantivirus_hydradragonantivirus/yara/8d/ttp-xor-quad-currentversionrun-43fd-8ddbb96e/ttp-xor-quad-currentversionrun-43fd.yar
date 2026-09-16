rule TTP_XOR_QUAD_CurrentVersionRun_43fd {
  strings:
    $key_43fd = { 10 92 [2] 34 9c [2] 1f b0 [2] 31 92 [2] 25 89 [2] 2a 93 [2] 34 8e [2] 36 8f [2] 2d 89 [2] 31 8e [2] 2d a1 }

  condition:
    any of them
}