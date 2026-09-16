rule TTP_XOR_QUAD_CurrentVersionRun_f619 {
  strings:
    $key_f619 = { a5 76 [2] 81 78 [2] aa 54 [2] 84 76 [2] 90 6d [2] 9f 77 [2] 81 6a [2] 83 6b [2] 98 6d [2] 84 6a [2] 98 45 }

  condition:
    any of them
}