rule TTP_XOR_QUAD_CurrentVersionRun_9dde {
  strings:
    $key_9dde = { ce b1 [2] ea bf [2] c1 93 [2] ef b1 [2] fb aa [2] f4 b0 [2] ea ad [2] e8 ac [2] f3 aa [2] ef ad [2] f3 82 }

  condition:
    any of them
}