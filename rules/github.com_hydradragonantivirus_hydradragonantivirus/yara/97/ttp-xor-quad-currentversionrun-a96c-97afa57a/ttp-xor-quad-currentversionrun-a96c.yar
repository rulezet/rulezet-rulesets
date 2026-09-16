rule TTP_XOR_QUAD_CurrentVersionRun_a96c {
  strings:
    $key_a96c = { fa 03 [2] de 0d [2] f5 21 [2] db 03 [2] cf 18 [2] c0 02 [2] de 1f [2] dc 1e [2] c7 18 [2] db 1f [2] c7 30 }

  condition:
    any of them
}