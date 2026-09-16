rule TTP_XOR_QUAD_CurrentVersionRun_a9ec {
  strings:
    $key_a9ec = { fa 83 [2] de 8d [2] f5 a1 [2] db 83 [2] cf 98 [2] c0 82 [2] de 9f [2] dc 9e [2] c7 98 [2] db 9f [2] c7 b0 }

  condition:
    any of them
}