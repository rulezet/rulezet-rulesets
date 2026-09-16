rule TTP_XOR_QUAD_CurrentVersionRun_9107 {
  strings:
    $key_9107 = { c2 68 [2] e6 66 [2] cd 4a [2] e3 68 [2] f7 73 [2] f8 69 [2] e6 74 [2] e4 75 [2] ff 73 [2] e3 74 [2] ff 5b }

  condition:
    any of them
}