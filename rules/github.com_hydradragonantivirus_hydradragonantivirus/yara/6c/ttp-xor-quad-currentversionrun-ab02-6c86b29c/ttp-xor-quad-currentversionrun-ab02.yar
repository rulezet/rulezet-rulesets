rule TTP_XOR_QUAD_CurrentVersionRun_ab02 {
  strings:
    $key_ab02 = { f8 6d [2] dc 63 [2] f7 4f [2] d9 6d [2] cd 76 [2] c2 6c [2] dc 71 [2] de 70 [2] c5 76 [2] d9 71 [2] c5 5e }

  condition:
    any of them
}