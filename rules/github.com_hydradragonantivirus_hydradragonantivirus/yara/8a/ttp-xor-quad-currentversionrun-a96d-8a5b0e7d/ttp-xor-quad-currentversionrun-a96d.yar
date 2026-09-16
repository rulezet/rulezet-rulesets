rule TTP_XOR_QUAD_CurrentVersionRun_a96d {
  strings:
    $key_a96d = { fa 02 [2] de 0c [2] f5 20 [2] db 02 [2] cf 19 [2] c0 03 [2] de 1e [2] dc 1f [2] c7 19 [2] db 1e [2] c7 31 }

  condition:
    any of them
}