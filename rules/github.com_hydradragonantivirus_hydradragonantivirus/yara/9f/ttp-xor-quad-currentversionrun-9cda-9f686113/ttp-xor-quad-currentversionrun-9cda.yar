rule TTP_XOR_QUAD_CurrentVersionRun_9cda {
  strings:
    $key_9cda = { cf b5 [2] eb bb [2] c0 97 [2] ee b5 [2] fa ae [2] f5 b4 [2] eb a9 [2] e9 a8 [2] f2 ae [2] ee a9 [2] f2 86 }

  condition:
    any of them
}