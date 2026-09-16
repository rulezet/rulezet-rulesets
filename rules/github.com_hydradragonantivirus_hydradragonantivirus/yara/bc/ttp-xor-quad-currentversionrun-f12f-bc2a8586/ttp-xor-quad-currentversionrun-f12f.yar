rule TTP_XOR_QUAD_CurrentVersionRun_f12f {
  strings:
    $key_f12f = { a2 40 [2] 86 4e [2] ad 62 [2] 83 40 [2] 97 5b [2] 98 41 [2] 86 5c [2] 84 5d [2] 9f 5b [2] 83 5c [2] 9f 73 }

  condition:
    any of them
}