rule TTP_XOR_QUAD_CurrentVersionRun_a92e {
  strings:
    $key_a92e = { fa 41 [2] de 4f [2] f5 63 [2] db 41 [2] cf 5a [2] c0 40 [2] de 5d [2] dc 5c [2] c7 5a [2] db 5d [2] c7 72 }

  condition:
    any of them
}