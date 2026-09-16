rule TTP_XOR_QUAD_CurrentVersionRun_8dc9 {
  strings:
    $key_8dc9 = { de a6 [2] fa a8 [2] d1 84 [2] ff a6 [2] eb bd [2] e4 a7 [2] fa ba [2] f8 bb [2] e3 bd [2] ff ba [2] e3 95 }

  condition:
    any of them
}