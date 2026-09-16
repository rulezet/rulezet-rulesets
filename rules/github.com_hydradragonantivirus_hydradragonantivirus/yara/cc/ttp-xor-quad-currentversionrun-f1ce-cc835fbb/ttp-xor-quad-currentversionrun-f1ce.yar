rule TTP_XOR_QUAD_CurrentVersionRun_f1ce {
  strings:
    $key_f1ce = { a2 a1 [2] 86 af [2] ad 83 [2] 83 a1 [2] 97 ba [2] 98 a0 [2] 86 bd [2] 84 bc [2] 9f ba [2] 83 bd [2] 9f 92 }

  condition:
    any of them
}