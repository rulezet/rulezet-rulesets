rule TTP_XOR_QUAD_CurrentVersionRun_adda {
  strings:
    $key_adda = { fe b5 [2] da bb [2] f1 97 [2] df b5 [2] cb ae [2] c4 b4 [2] da a9 [2] d8 a8 [2] c3 ae [2] df a9 [2] c3 86 }

  condition:
    any of them
}