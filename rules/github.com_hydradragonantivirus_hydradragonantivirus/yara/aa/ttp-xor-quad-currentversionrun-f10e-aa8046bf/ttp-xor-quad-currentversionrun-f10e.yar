rule TTP_XOR_QUAD_CurrentVersionRun_f10e {
  strings:
    $key_f10e = { a2 61 [2] 86 6f [2] ad 43 [2] 83 61 [2] 97 7a [2] 98 60 [2] 86 7d [2] 84 7c [2] 9f 7a [2] 83 7d [2] 9f 52 }

  condition:
    any of them
}