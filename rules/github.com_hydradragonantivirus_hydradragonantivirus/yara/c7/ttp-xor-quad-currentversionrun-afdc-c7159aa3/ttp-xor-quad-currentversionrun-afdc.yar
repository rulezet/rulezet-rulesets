rule TTP_XOR_QUAD_CurrentVersionRun_afdc {
  strings:
    $key_afdc = { fc b3 [2] d8 bd [2] f3 91 [2] dd b3 [2] c9 a8 [2] c6 b2 [2] d8 af [2] da ae [2] c1 a8 [2] dd af [2] c1 80 }

  condition:
    any of them
}