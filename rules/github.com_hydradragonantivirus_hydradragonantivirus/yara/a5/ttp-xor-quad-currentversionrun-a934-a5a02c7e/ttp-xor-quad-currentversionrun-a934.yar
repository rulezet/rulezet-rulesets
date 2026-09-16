rule TTP_XOR_QUAD_CurrentVersionRun_a934 {
  strings:
    $key_a934 = { fa 5b [2] de 55 [2] f5 79 [2] db 5b [2] cf 40 [2] c0 5a [2] de 47 [2] dc 46 [2] c7 40 [2] db 47 [2] c7 68 }

  condition:
    any of them
}