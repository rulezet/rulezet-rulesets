rule TTP_XOR_QUAD_CurrentVersionRun_f63e {
  strings:
    $key_f63e = { a5 51 [2] 81 5f [2] aa 73 [2] 84 51 [2] 90 4a [2] 9f 50 [2] 81 4d [2] 83 4c [2] 98 4a [2] 84 4d [2] 98 62 }

  condition:
    any of them
}