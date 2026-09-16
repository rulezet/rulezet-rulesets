rule TTP_XOR_QUAD_CurrentVersionRun_8bbf {
  strings:
    $key_8bbf = { d8 d0 [2] fc de [2] d7 f2 [2] f9 d0 [2] ed cb [2] e2 d1 [2] fc cc [2] fe cd [2] e5 cb [2] f9 cc [2] e5 e3 }

  condition:
    any of them
}