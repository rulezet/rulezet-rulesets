rule TTP_XOR_QUAD_CurrentVersionRun_f011 {
  strings:
    $key_f011 = { a3 7e [2] 87 70 [2] ac 5c [2] 82 7e [2] 96 65 [2] 99 7f [2] 87 62 [2] 85 63 [2] 9e 65 [2] 82 62 [2] 9e 4d }

  condition:
    any of them
}