rule TTP_XOR_QUAD_CurrentVersionRun_92f6 {
  strings:
    $key_92f6 = { c1 99 [2] e5 97 [2] ce bb [2] e0 99 [2] f4 82 [2] fb 98 [2] e5 85 [2] e7 84 [2] fc 82 [2] e0 85 [2] fc aa }

  condition:
    any of them
}