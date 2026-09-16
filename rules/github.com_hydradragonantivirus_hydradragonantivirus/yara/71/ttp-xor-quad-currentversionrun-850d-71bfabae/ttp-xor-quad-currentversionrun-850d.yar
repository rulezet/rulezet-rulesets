rule TTP_XOR_QUAD_CurrentVersionRun_850d {
  strings:
    $key_850d = { d6 62 [2] f2 6c [2] d9 40 [2] f7 62 [2] e3 79 [2] ec 63 [2] f2 7e [2] f0 7f [2] eb 79 [2] f7 7e [2] eb 51 }

  condition:
    any of them
}