rule TTP_XOR_QUAD_CurrentVersionRun_081f {
  strings:
    $key_081f = { 5b 70 [2] 7f 7e [2] 54 52 [2] 7a 70 [2] 6e 6b [2] 61 71 [2] 7f 6c [2] 7d 6d [2] 66 6b [2] 7a 6c [2] 66 43 }

  condition:
    any of them
}