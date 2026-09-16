rule TTP_XOR_QUAD_CurrentVersionRun_f12c {
  strings:
    $key_f12c = { a2 43 [2] 86 4d [2] ad 61 [2] 83 43 [2] 97 58 [2] 98 42 [2] 86 5f [2] 84 5e [2] 9f 58 [2] 83 5f [2] 9f 70 }

  condition:
    any of them
}