rule TTP_XOR_QUAD_CurrentVersionRun_95fe {
  strings:
    $key_95fe = { c6 91 [2] e2 9f [2] c9 b3 [2] e7 91 [2] f3 8a [2] fc 90 [2] e2 8d [2] e0 8c [2] fb 8a [2] e7 8d [2] fb a2 }

  condition:
    any of them
}