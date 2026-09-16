rule TTP_XOR_QUAD_CurrentVersionRun_923b {
  strings:
    $key_923b = { c1 54 [2] e5 5a [2] ce 76 [2] e0 54 [2] f4 4f [2] fb 55 [2] e5 48 [2] e7 49 [2] fc 4f [2] e0 48 [2] fc 67 }

  condition:
    any of them
}