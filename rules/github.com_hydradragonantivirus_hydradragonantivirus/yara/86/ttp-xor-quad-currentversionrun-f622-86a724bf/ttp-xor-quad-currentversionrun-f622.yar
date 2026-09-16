rule TTP_XOR_QUAD_CurrentVersionRun_f622 {
  strings:
    $key_f622 = { a5 4d [2] 81 43 [2] aa 6f [2] 84 4d [2] 90 56 [2] 9f 4c [2] 81 51 [2] 83 50 [2] 98 56 [2] 84 51 [2] 98 7e }

  condition:
    any of them
}