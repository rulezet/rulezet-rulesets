rule TTP_XOR_QUAD_CurrentVersionRun_f22f {
  strings:
    $key_f22f = { a1 40 [2] 85 4e [2] ae 62 [2] 80 40 [2] 94 5b [2] 9b 41 [2] 85 5c [2] 87 5d [2] 9c 5b [2] 80 5c [2] 9c 73 }

  condition:
    any of them
}