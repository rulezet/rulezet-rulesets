rule TTP_XOR_QUAD_CurrentVersionRun_a90f {
  strings:
    $key_a90f = { fa 60 [2] de 6e [2] f5 42 [2] db 60 [2] cf 7b [2] c0 61 [2] de 7c [2] dc 7d [2] c7 7b [2] db 7c [2] c7 53 }

  condition:
    any of them
}