rule TTP_XOR_QUAD_CurrentVersionRun_261f {
  strings:
    $key_261f = { 75 70 [2] 51 7e [2] 7a 52 [2] 54 70 [2] 40 6b [2] 4f 71 [2] 51 6c [2] 53 6d [2] 48 6b [2] 54 6c [2] 48 43 }

  condition:
    any of them
}