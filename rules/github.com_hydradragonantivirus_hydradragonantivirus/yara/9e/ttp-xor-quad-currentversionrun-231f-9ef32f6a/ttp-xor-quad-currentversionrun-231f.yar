rule TTP_XOR_QUAD_CurrentVersionRun_231f {
  strings:
    $key_231f = { 70 70 [2] 54 7e [2] 7f 52 [2] 51 70 [2] 45 6b [2] 4a 71 [2] 54 6c [2] 56 6d [2] 4d 6b [2] 51 6c [2] 4d 43 }

  condition:
    any of them
}