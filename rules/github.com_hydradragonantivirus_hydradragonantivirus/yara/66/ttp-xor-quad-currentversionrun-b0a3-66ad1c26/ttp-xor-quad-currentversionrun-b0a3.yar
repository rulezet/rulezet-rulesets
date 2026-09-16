rule TTP_XOR_QUAD_CurrentVersionRun_b0a3 {
  strings:
    $key_b0a3 = { e3 cc [2] c7 c2 [2] ec ee [2] c2 cc [2] d6 d7 [2] d9 cd [2] c7 d0 [2] c5 d1 [2] de d7 [2] c2 d0 [2] de ff }

  condition:
    any of them
}