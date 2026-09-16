rule TTP_XOR_QUAD_CurrentVersionRun_f13f {
  strings:
    $key_f13f = { a2 50 [2] 86 5e [2] ad 72 [2] 83 50 [2] 97 4b [2] 98 51 [2] 86 4c [2] 84 4d [2] 9f 4b [2] 83 4c [2] 9f 63 }

  condition:
    any of them
}