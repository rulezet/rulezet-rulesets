rule TTP_XOR_QUAD_CurrentVersionRun_e42c {
  strings:
    $key_e42c = { b7 43 [2] 93 4d [2] b8 61 [2] 96 43 [2] 82 58 [2] 8d 42 [2] 93 5f [2] 91 5e [2] 8a 58 [2] 96 5f [2] 8a 70 }

  condition:
    any of them
}