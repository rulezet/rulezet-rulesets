rule TTP_XOR_QUAD_CurrentVersionRun_f11f {
  strings:
    $key_f11f = { a2 70 [2] 86 7e [2] ad 52 [2] 83 70 [2] 97 6b [2] 98 71 [2] 86 6c [2] 84 6d [2] 9f 6b [2] 83 6c [2] 9f 43 }

  condition:
    any of them
}