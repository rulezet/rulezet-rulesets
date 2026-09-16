rule TTP_XOR_QUAD_CurrentVersionRun_932f {
  strings:
    $key_932f = { c0 40 [2] e4 4e [2] cf 62 [2] e1 40 [2] f5 5b [2] fa 41 [2] e4 5c [2] e6 5d [2] fd 5b [2] e1 5c [2] fd 73 }

  condition:
    any of them
}