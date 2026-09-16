rule TTP_XOR_QUAD_CurrentVersionRun_8211 {
  strings:
    $key_8211 = { d1 7e [2] f5 70 [2] de 5c [2] f0 7e [2] e4 65 [2] eb 7f [2] f5 62 [2] f7 63 [2] ec 65 [2] f0 62 [2] ec 4d }

  condition:
    any of them
}