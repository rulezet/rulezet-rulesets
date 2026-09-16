rule TTP_XOR_QUAD_CurrentVersionRun_2d1f {
  strings:
    $key_2d1f = { 7e 70 [2] 5a 7e [2] 71 52 [2] 5f 70 [2] 4b 6b [2] 44 71 [2] 5a 6c [2] 58 6d [2] 43 6b [2] 5f 6c [2] 43 43 }

  condition:
    any of them
}