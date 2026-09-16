rule TTP_XOR_QUAD_CurrentVersionRun_8e97 {
  strings:
    $key_8e97 = { dd f8 [2] f9 f6 [2] d2 da [2] fc f8 [2] e8 e3 [2] e7 f9 [2] f9 e4 [2] fb e5 [2] e0 e3 [2] fc e4 [2] e0 cb }

  condition:
    any of them
}