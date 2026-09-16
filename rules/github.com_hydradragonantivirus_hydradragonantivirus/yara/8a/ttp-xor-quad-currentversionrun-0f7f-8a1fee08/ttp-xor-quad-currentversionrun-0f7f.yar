rule TTP_XOR_QUAD_CurrentVersionRun_0f7f {
  strings:
    $key_0f7f = { 5c 10 [2] 78 1e [2] 53 32 [2] 7d 10 [2] 69 0b [2] 66 11 [2] 78 0c [2] 7a 0d [2] 61 0b [2] 7d 0c [2] 61 23 }

  condition:
    any of them
}