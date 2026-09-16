rule TTP_XOR_QUAD_CurrentVersionRun_a89a {
  strings:
    $key_a89a = { fb f5 [2] df fb [2] f4 d7 [2] da f5 [2] ce ee [2] c1 f4 [2] df e9 [2] dd e8 [2] c6 ee [2] da e9 [2] c6 c6 }

  condition:
    any of them
}