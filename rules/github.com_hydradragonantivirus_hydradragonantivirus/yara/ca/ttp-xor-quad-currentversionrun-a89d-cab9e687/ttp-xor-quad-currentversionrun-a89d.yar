rule TTP_XOR_QUAD_CurrentVersionRun_a89d {
  strings:
    $key_a89d = { fb f2 [2] df fc [2] f4 d0 [2] da f2 [2] ce e9 [2] c1 f3 [2] df ee [2] dd ef [2] c6 e9 [2] da ee [2] c6 c1 }

  condition:
    any of them
}