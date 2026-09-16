rule TTP_XOR_QUAD_CurrentVersionRun_a92f {
  strings:
    $key_a92f = { fa 40 [2] de 4e [2] f5 62 [2] db 40 [2] cf 5b [2] c0 41 [2] de 5c [2] dc 5d [2] c7 5b [2] db 5c [2] c7 73 }

  condition:
    any of them
}