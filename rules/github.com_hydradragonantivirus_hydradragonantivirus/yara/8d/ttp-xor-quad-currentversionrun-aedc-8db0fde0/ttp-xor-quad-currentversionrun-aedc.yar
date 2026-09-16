rule TTP_XOR_QUAD_CurrentVersionRun_aedc {
  strings:
    $key_aedc = { fd b3 [2] d9 bd [2] f2 91 [2] dc b3 [2] c8 a8 [2] c7 b2 [2] d9 af [2] db ae [2] c0 a8 [2] dc af [2] c0 80 }

  condition:
    any of them
}