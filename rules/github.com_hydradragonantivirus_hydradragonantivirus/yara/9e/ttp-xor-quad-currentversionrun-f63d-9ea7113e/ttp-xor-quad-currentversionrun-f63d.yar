rule TTP_XOR_QUAD_CurrentVersionRun_f63d {
  strings:
    $key_f63d = { a5 52 [2] 81 5c [2] aa 70 [2] 84 52 [2] 90 49 [2] 9f 53 [2] 81 4e [2] 83 4f [2] 98 49 [2] 84 4e [2] 98 61 }

  condition:
    any of them
}