rule TTP_XOR_QUAD_CurrentVersionRun_a8f1 {
  strings:
    $key_a8f1 = { fb 9e [2] df 90 [2] f4 bc [2] da 9e [2] ce 85 [2] c1 9f [2] df 82 [2] dd 83 [2] c6 85 [2] da 82 [2] c6 ad }

  condition:
    any of them
}