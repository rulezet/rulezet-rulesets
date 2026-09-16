rule TTP_XOR_QUAD_CurrentVersionRun_aedb {
  strings:
    $key_aedb = { fd b4 [2] d9 ba [2] f2 96 [2] dc b4 [2] c8 af [2] c7 b5 [2] d9 a8 [2] db a9 [2] c0 af [2] dc a8 [2] c0 87 }

  condition:
    any of them
}