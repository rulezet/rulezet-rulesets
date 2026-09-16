rule TTP_XOR_QUAD_CurrentVersionRun_932d {
  strings:
    $key_932d = { c0 42 [2] e4 4c [2] cf 60 [2] e1 42 [2] f5 59 [2] fa 43 [2] e4 5e [2] e6 5f [2] fd 59 [2] e1 5e [2] fd 71 }

  condition:
    any of them
}