rule Crypton_v1__32_big_AND_ {
  strings:
    $a0 = { ac ac ac ac [0-20] 59 59 59 59 [0-20] b2 b2 b2 b2 [0-20] 65 65 65 65 [0-20] 01 01 01 01 [0-20] 3f cf f3 fc [0-20] fc 3f cf f3 [0-20] f3 fc 3f cf [0-20] cf f3 fc 3f }

  condition:
    $a0
}