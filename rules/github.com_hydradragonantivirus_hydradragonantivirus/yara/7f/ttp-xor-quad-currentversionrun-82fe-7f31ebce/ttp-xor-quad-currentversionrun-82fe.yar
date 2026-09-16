rule TTP_XOR_QUAD_CurrentVersionRun_82fe {
  strings:
    $key_82fe = { d1 91 [2] f5 9f [2] de b3 [2] f0 91 [2] e4 8a [2] eb 90 [2] f5 8d [2] f7 8c [2] ec 8a [2] f0 8d [2] ec a2 }

  condition:
    any of them
}