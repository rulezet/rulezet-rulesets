rule TTP_XOR_QUAD_CurrentVersionRun_f90f {
  strings:
    $key_f90f = { aa 60 [2] 8e 6e [2] a5 42 [2] 8b 60 [2] 9f 7b [2] 90 61 [2] 8e 7c [2] 8c 7d [2] 97 7b [2] 8b 7c [2] 97 53 }

  condition:
    any of them
}