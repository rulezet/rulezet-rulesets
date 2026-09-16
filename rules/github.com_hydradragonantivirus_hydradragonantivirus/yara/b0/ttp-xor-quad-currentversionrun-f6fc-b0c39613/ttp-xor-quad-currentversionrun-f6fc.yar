rule TTP_XOR_QUAD_CurrentVersionRun_f6fc {
  strings:
    $key_f6fc = { a5 93 [2] 81 9d [2] aa b1 [2] 84 93 [2] 90 88 [2] 9f 92 [2] 81 8f [2] 83 8e [2] 98 88 [2] 84 8f [2] 98 a0 }

  condition:
    any of them
}