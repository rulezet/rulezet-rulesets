rule TTP_XOR_QUAD_CurrentVersionRun_e42e {
  strings:
    $key_e42e = { b7 41 [2] 93 4f [2] b8 63 [2] 96 41 [2] 82 5a [2] 8d 40 [2] 93 5d [2] 91 5c [2] 8a 5a [2] 96 5d [2] 8a 72 }

  condition:
    any of them
}