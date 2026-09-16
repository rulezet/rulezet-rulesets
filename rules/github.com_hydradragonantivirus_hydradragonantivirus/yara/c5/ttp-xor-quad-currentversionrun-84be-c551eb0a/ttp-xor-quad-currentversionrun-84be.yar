rule TTP_XOR_QUAD_CurrentVersionRun_84be {
  strings:
    $key_84be = { d7 d1 [2] f3 df [2] d8 f3 [2] f6 d1 [2] e2 ca [2] ed d0 [2] f3 cd [2] f1 cc [2] ea ca [2] f6 cd [2] ea e2 }

  condition:
    any of them
}