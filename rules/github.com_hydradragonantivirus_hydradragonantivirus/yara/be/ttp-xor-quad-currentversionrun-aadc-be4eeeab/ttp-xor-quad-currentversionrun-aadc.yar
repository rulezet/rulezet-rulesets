rule TTP_XOR_QUAD_CurrentVersionRun_aadc {
  strings:
    $key_aadc = { f9 b3 [2] dd bd [2] f6 91 [2] d8 b3 [2] cc a8 [2] c3 b2 [2] dd af [2] df ae [2] c4 a8 [2] d8 af [2] c4 80 }

  condition:
    any of them
}