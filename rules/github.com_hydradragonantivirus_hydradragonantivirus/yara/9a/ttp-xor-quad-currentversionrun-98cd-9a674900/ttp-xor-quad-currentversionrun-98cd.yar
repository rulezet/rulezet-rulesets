rule TTP_XOR_QUAD_CurrentVersionRun_98cd {
  strings:
    $key_98cd = { cb a2 [2] ef ac [2] c4 80 [2] ea a2 [2] fe b9 [2] f1 a3 [2] ef be [2] ed bf [2] f6 b9 [2] ea be [2] f6 91 }

  condition:
    any of them
}