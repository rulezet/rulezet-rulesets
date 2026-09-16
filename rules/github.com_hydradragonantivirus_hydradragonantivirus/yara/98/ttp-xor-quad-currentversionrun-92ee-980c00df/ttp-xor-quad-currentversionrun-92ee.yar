rule TTP_XOR_QUAD_CurrentVersionRun_92ee {
  strings:
    $key_92ee = { c1 81 [2] e5 8f [2] ce a3 [2] e0 81 [2] f4 9a [2] fb 80 [2] e5 9d [2] e7 9c [2] fc 9a [2] e0 9d [2] fc b2 }

  condition:
    any of them
}