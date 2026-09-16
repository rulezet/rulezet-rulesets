rule TTP_XOR_QUAD_CurrentVersionRun_f24a {
  strings:
    $key_f24a = { a1 25 [2] 85 2b [2] ae 07 [2] 80 25 [2] 94 3e [2] 9b 24 [2] 85 39 [2] 87 38 [2] 9c 3e [2] 80 39 [2] 9c 16 }

  condition:
    any of them
}