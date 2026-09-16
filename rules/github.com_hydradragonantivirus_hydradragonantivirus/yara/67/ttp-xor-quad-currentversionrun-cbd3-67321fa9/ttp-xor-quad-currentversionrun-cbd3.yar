rule TTP_XOR_QUAD_CurrentVersionRun_cbd3 {
  strings:
    $key_cbd3 = { 98 bc [2] bc b2 [2] 97 9e [2] b9 bc [2] ad a7 [2] a2 bd [2] bc a0 [2] be a1 [2] a5 a7 [2] b9 a0 [2] a5 8f }

  condition:
    any of them
}