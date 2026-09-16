rule TTP_XOR_QUAD_CurrentVersionRun_f6ef {
  strings:
    $key_f6ef = { a5 80 [2] 81 8e [2] aa a2 [2] 84 80 [2] 90 9b [2] 9f 81 [2] 81 9c [2] 83 9d [2] 98 9b [2] 84 9c [2] 98 b3 }

  condition:
    any of them
}