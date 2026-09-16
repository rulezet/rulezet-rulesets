rule TTP_XOR_QUAD_CurrentVersionRun_f612 {
  strings:
    $key_f612 = { a5 7d [2] 81 73 [2] aa 5f [2] 84 7d [2] 90 66 [2] 9f 7c [2] 81 61 [2] 83 60 [2] 98 66 [2] 84 61 [2] 98 4e }

  condition:
    any of them
}