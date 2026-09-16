rule TTP_XOR_QUAD_CurrentVersionRun_923c {
  strings:
    $key_923c = { c1 53 [2] e5 5d [2] ce 71 [2] e0 53 [2] f4 48 [2] fb 52 [2] e5 4f [2] e7 4e [2] fc 48 [2] e0 4f [2] fc 60 }

  condition:
    any of them
}