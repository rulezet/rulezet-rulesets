rule TTP_XOR_QUAD_CurrentVersionRun_a9fe {
  strings:
    $key_a9fe = { fa 91 [2] de 9f [2] f5 b3 [2] db 91 [2] cf 8a [2] c0 90 [2] de 8d [2] dc 8c [2] c7 8a [2] db 8d [2] c7 a2 }

  condition:
    any of them
}