rule TTP_XOR_QUAD_CurrentVersionRun_a971 {
  strings:
    $key_a971 = { fa 1e [2] de 10 [2] f5 3c [2] db 1e [2] cf 05 [2] c0 1f [2] de 02 [2] dc 03 [2] c7 05 [2] db 02 [2] c7 2d }

  condition:
    any of them
}