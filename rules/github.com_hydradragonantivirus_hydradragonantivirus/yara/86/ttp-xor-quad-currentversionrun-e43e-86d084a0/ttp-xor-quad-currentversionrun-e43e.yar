rule TTP_XOR_QUAD_CurrentVersionRun_e43e {
  strings:
    $key_e43e = { b7 51 [2] 93 5f [2] b8 73 [2] 96 51 [2] 82 4a [2] 8d 50 [2] 93 4d [2] 91 4c [2] 8a 4a [2] 96 4d [2] 8a 62 }

  condition:
    any of them
}