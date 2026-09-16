rule TTP_XOR_QUAD_CurrentVersionRun_8570 {
  strings:
    $key_8570 = { d6 1f [2] f2 11 [2] d9 3d [2] f7 1f [2] e3 04 [2] ec 1e [2] f2 03 [2] f0 02 [2] eb 04 [2] f7 03 [2] eb 2c }

  condition:
    any of them
}