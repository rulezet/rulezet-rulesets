rule TTP_XOR_QUAD_CurrentVersionRun_21ef {
  strings:
    $key_21ef = { 72 80 [2] 56 8e [2] 7d a2 [2] 53 80 [2] 47 9b [2] 48 81 [2] 56 9c [2] 54 9d [2] 4f 9b [2] 53 9c [2] 4f b3 }

  condition:
    any of them
}