rule TTP_XOR_QUAD_CurrentVersionRun_a88c {
  strings:
    $key_a88c = { fb e3 [2] df ed [2] f4 c1 [2] da e3 [2] ce f8 [2] c1 e2 [2] df ff [2] dd fe [2] c6 f8 [2] da ff [2] c6 d0 }

  condition:
    any of them
}