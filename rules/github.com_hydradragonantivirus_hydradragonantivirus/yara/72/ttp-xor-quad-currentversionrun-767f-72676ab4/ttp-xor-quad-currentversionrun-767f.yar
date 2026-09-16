rule TTP_XOR_QUAD_CurrentVersionRun_767f {
  strings:
    $key_767f = { 25 10 [2] 01 1e [2] 2a 32 [2] 04 10 [2] 10 0b [2] 1f 11 [2] 01 0c [2] 03 0d [2] 18 0b [2] 04 0c [2] 18 23 }

  condition:
    any of them
}