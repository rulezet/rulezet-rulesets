rule TTP_XOR_QUAD_CurrentVersionRun_92e0 {
  strings:
    $key_92e0 = { c1 8f [2] e5 81 [2] ce ad [2] e0 8f [2] f4 94 [2] fb 8e [2] e5 93 [2] e7 92 [2] fc 94 [2] e0 93 [2] fc bc }

  condition:
    any of them
}