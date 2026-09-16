rule TTP_XOR_QUAD_CurrentVersionRun_7e1f {
  strings:
    $key_7e1f = { 2d 70 [2] 09 7e [2] 22 52 [2] 0c 70 [2] 18 6b [2] 17 71 [2] 09 6c [2] 0b 6d [2] 10 6b [2] 0c 6c [2] 10 43 }

  condition:
    any of them
}