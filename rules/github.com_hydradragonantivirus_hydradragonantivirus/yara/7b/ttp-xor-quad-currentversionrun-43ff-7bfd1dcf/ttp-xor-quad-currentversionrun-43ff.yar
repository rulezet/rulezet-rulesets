rule TTP_XOR_QUAD_CurrentVersionRun_43ff {
  strings:
    $key_43ff = { 10 90 [2] 34 9e [2] 1f b2 [2] 31 90 [2] 25 8b [2] 2a 91 [2] 34 8c [2] 36 8d [2] 2d 8b [2] 31 8c [2] 2d a3 }

  condition:
    any of them
}