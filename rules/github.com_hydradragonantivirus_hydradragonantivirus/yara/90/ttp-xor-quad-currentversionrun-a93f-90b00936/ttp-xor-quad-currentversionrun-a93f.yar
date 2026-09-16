rule TTP_XOR_QUAD_CurrentVersionRun_a93f {
  strings:
    $key_a93f = { fa 50 [2] de 5e [2] f5 72 [2] db 50 [2] cf 4b [2] c0 51 [2] de 4c [2] dc 4d [2] c7 4b [2] db 4c [2] c7 63 }

  condition:
    any of them
}