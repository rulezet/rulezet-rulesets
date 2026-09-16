rule TTP_XOR_QUAD_CurrentVersionRun_abe2 {
  strings:
    $key_abe2 = { f8 8d [2] dc 83 [2] f7 af [2] d9 8d [2] cd 96 [2] c2 8c [2] dc 91 [2] de 90 [2] c5 96 [2] d9 91 [2] c5 be }

  condition:
    any of them
}