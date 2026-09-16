rule TTP_XOR_QUAD_CurrentVersionRun_a90e {
  strings:
    $key_a90e = { fa 61 [2] de 6f [2] f5 43 [2] db 61 [2] cf 7a [2] c0 60 [2] de 7d [2] dc 7c [2] c7 7a [2] db 7d [2] c7 52 }

  condition:
    any of them
}