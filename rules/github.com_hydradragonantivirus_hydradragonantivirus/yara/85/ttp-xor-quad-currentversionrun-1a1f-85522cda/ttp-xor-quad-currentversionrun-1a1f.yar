rule TTP_XOR_QUAD_CurrentVersionRun_1a1f {
  strings:
    $key_1a1f = { 49 70 [2] 6d 7e [2] 46 52 [2] 68 70 [2] 7c 6b [2] 73 71 [2] 6d 6c [2] 6f 6d [2] 74 6b [2] 68 6c [2] 74 43 }

  condition:
    any of them
}