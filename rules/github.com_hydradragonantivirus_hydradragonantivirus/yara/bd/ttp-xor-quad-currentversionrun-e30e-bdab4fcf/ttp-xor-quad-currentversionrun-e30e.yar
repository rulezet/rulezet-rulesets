rule TTP_XOR_QUAD_CurrentVersionRun_e30e {
  strings:
    $key_e30e = { b0 61 [2] 94 6f [2] bf 43 [2] 91 61 [2] 85 7a [2] 8a 60 [2] 94 7d [2] 96 7c [2] 8d 7a [2] 91 7d [2] 8d 52 }

  condition:
    any of them
}