rule TTP_XOR_QUAD_CurrentVersionRun_853f {
  strings:
    $key_853f = { d6 50 [2] f2 5e [2] d9 72 [2] f7 50 [2] e3 4b [2] ec 51 [2] f2 4c [2] f0 4d [2] eb 4b [2] f7 4c [2] eb 63 }

  condition:
    any of them
}