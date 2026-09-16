rule TTP_XOR_QUAD_CurrentVersionRun_8230 {
  strings:
    $key_8230 = { d1 5f [2] f5 51 [2] de 7d [2] f0 5f [2] e4 44 [2] eb 5e [2] f5 43 [2] f7 42 [2] ec 44 [2] f0 43 [2] ec 6c }

  condition:
    any of them
}