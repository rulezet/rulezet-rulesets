rule TTP_XOR_QUAD_CurrentVersionRun_f10f {
  strings:
    $key_f10f = { a2 60 [2] 86 6e [2] ad 42 [2] 83 60 [2] 97 7b [2] 98 61 [2] 86 7c [2] 84 7d [2] 9f 7b [2] 83 7c [2] 9f 53 }

  condition:
    any of them
}