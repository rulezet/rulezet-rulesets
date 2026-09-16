rule TTP_XOR_QUAD_CurrentVersionRun_f111 {
  strings:
    $key_f111 = { a2 7e [2] 86 70 [2] ad 5c [2] 83 7e [2] 97 65 [2] 98 7f [2] 86 62 [2] 84 63 [2] 9f 65 [2] 83 62 [2] 9f 4d }

  condition:
    any of them
}