rule TTP_XOR_QUAD_CurrentVersionRun_923d {
  strings:
    $key_923d = { c1 52 [2] e5 5c [2] ce 70 [2] e0 52 [2] f4 49 [2] fb 53 [2] e5 4e [2] e7 4f [2] fc 49 [2] e0 4e [2] fc 61 }

  condition:
    any of them
}