rule TTP_XOR_QUAD_CurrentVersionRun_a933 {
  strings:
    $key_a933 = { fa 5c [2] de 52 [2] f5 7e [2] db 5c [2] cf 47 [2] c0 5d [2] de 40 [2] dc 41 [2] c7 47 [2] db 40 [2] c7 6f }

  condition:
    any of them
}