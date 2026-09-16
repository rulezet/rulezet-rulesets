rule TTP_XOR_QUAD_CurrentVersionRun_d9a3 {
  strings:
    $key_d9a3 = { 8a cc [2] ae c2 [2] 85 ee [2] ab cc [2] bf d7 [2] b0 cd [2] ae d0 [2] ac d1 [2] b7 d7 [2] ab d0 [2] b7 ff }

  condition:
    any of them
}