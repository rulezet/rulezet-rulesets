rule TTP_XOR_QUAD_CurrentVersionRun_6d1f {
  strings:
    $key_6d1f = { 3e 70 [2] 1a 7e [2] 31 52 [2] 1f 70 [2] 0b 6b [2] 04 71 [2] 1a 6c [2] 18 6d [2] 03 6b [2] 1f 6c [2] 03 43 }

  condition:
    any of them
}