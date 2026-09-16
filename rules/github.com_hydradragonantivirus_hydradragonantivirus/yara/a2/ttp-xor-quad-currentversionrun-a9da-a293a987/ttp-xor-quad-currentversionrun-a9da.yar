rule TTP_XOR_QUAD_CurrentVersionRun_a9da {
  strings:
    $key_a9da = { fa b5 [2] de bb [2] f5 97 [2] db b5 [2] cf ae [2] c0 b4 [2] de a9 [2] dc a8 [2] c7 ae [2] db a9 [2] c7 86 }

  condition:
    any of them
}