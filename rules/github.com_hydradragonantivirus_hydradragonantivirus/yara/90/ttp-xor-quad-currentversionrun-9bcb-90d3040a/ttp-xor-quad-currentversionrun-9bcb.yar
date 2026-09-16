rule TTP_XOR_QUAD_CurrentVersionRun_9bcb {
  strings:
    $key_9bcb = { c8 a4 [2] ec aa [2] c7 86 [2] e9 a4 [2] fd bf [2] f2 a5 [2] ec b8 [2] ee b9 [2] f5 bf [2] e9 b8 [2] f5 97 }

  condition:
    any of them
}