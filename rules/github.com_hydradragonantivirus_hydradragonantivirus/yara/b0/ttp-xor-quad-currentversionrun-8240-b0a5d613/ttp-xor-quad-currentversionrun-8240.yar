rule TTP_XOR_QUAD_CurrentVersionRun_8240 {
  strings:
    $key_8240 = { d1 2f [2] f5 21 [2] de 0d [2] f0 2f [2] e4 34 [2] eb 2e [2] f5 33 [2] f7 32 [2] ec 34 [2] f0 33 [2] ec 1c }

  condition:
    any of them
}