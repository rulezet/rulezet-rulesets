rule TTP_XOR_QUAD_CurrentVersionRun_a8cc {
  strings:
    $key_a8cc = { fb a3 [2] df ad [2] f4 81 [2] da a3 [2] ce b8 [2] c1 a2 [2] df bf [2] dd be [2] c6 b8 [2] da bf [2] c6 90 }

  condition:
    any of them
}