rule TTP_XOR_QUAD_CurrentVersionRun_9d92 {
  strings:
    $key_9d92 = { ce fd [2] ea f3 [2] c1 df [2] ef fd [2] fb e6 [2] f4 fc [2] ea e1 [2] e8 e0 [2] f3 e6 [2] ef e1 [2] f3 ce }

  condition:
    any of them
}