rule TTP_XOR_QUAD_CurrentVersionRun_441f {
  strings:
    $key_441f = { 17 70 [2] 33 7e [2] 18 52 [2] 36 70 [2] 22 6b [2] 2d 71 [2] 33 6c [2] 31 6d [2] 2a 6b [2] 36 6c [2] 2a 43 }

  condition:
    any of them
}