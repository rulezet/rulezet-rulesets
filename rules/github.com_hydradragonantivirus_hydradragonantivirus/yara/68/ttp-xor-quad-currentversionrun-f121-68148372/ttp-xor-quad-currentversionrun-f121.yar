rule TTP_XOR_QUAD_CurrentVersionRun_f121 {
  strings:
    $key_f121 = { a2 4e [2] 86 40 [2] ad 6c [2] 83 4e [2] 97 55 [2] 98 4f [2] 86 52 [2] 84 53 [2] 9f 55 [2] 83 52 [2] 9f 7d }

  condition:
    any of them
}