rule TTP_XOR_QUAD_CurrentVersionRun_781f {
  strings:
    $key_781f = { 2b 70 [2] 0f 7e [2] 24 52 [2] 0a 70 [2] 1e 6b [2] 11 71 [2] 0f 6c [2] 0d 6d [2] 16 6b [2] 0a 6c [2] 16 43 }

  condition:
    any of them
}