rule TTP_XOR_QUAD_CurrentVersionRun_932e {
  strings:
    $key_932e = { c0 41 [2] e4 4f [2] cf 63 [2] e1 41 [2] f5 5a [2] fa 40 [2] e4 5d [2] e6 5c [2] fd 5a [2] e1 5d [2] fd 72 }

  condition:
    any of them
}