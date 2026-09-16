rule TTP_XOR_QUAD_CurrentVersionRun_f301 {
  strings:
    $key_f301 = { a0 6e [2] 84 60 [2] af 4c [2] 81 6e [2] 95 75 [2] 9a 6f [2] 84 72 [2] 86 73 [2] 9d 75 [2] 81 72 [2] 9d 5d }

  condition:
    any of them
}