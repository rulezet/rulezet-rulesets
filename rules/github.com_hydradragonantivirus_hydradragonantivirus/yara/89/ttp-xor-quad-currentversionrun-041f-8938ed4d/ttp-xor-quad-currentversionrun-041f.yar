rule TTP_XOR_QUAD_CurrentVersionRun_041f {
  strings:
    $key_041f = { 57 70 [2] 73 7e [2] 58 52 [2] 76 70 [2] 62 6b [2] 6d 71 [2] 73 6c [2] 71 6d [2] 6a 6b [2] 76 6c [2] 6a 43 }

  condition:
    any of them
}