rule TTP_XOR_QUAD_CurrentVersionRun_a80e {
  strings:
    $key_a80e = { fb 61 [2] df 6f [2] f4 43 [2] da 61 [2] ce 7a [2] c1 60 [2] df 7d [2] dd 7c [2] c6 7a [2] da 7d [2] c6 52 }

  condition:
    any of them
}