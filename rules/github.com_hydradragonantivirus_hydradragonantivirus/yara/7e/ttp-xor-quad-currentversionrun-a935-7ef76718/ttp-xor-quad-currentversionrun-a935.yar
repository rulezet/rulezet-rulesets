rule TTP_XOR_QUAD_CurrentVersionRun_a935 {
  strings:
    $key_a935 = { fa 5a [2] de 54 [2] f5 78 [2] db 5a [2] cf 41 [2] c0 5b [2] de 46 [2] dc 47 [2] c7 41 [2] db 46 [2] c7 69 }

  condition:
    any of them
}