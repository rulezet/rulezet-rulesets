rule TTP_XOR_QUAD_CurrentVersionRun_a852 {
  strings:
    $key_a852 = { fb 3d [2] df 33 [2] f4 1f [2] da 3d [2] ce 26 [2] c1 3c [2] df 21 [2] dd 20 [2] c6 26 [2] da 21 [2] c6 0e }

  condition:
    any of them
}