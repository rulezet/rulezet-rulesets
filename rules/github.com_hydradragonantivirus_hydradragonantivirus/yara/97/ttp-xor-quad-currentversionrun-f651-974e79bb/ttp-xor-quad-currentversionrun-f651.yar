rule TTP_XOR_QUAD_CurrentVersionRun_f651 {
  strings:
    $key_f651 = { a5 3e [2] 81 30 [2] aa 1c [2] 84 3e [2] 90 25 [2] 9f 3f [2] 81 22 [2] 83 23 [2] 98 25 [2] 84 22 [2] 98 0d }

  condition:
    any of them
}