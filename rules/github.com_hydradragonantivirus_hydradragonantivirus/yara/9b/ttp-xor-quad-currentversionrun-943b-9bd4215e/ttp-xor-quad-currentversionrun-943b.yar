rule TTP_XOR_QUAD_CurrentVersionRun_943b {
  strings:
    $key_943b = { c7 54 [2] e3 5a [2] c8 76 [2] e6 54 [2] f2 4f [2] fd 55 [2] e3 48 [2] e1 49 [2] fa 4f [2] e6 48 [2] fa 67 }

  condition:
    any of them
}