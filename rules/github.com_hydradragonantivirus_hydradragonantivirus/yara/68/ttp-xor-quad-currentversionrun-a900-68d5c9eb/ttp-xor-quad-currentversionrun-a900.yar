rule TTP_XOR_QUAD_CurrentVersionRun_a900 {
  strings:
    $key_a900 = { fa 6f [2] de 61 [2] f5 4d [2] db 6f [2] cf 74 [2] c0 6e [2] de 73 [2] dc 72 [2] c7 74 [2] db 73 [2] c7 5c }

  condition:
    any of them
}