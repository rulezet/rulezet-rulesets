rule TTP_XOR_QUAD_CurrentVersionRun_8528 {
  strings:
    $key_8528 = { d6 47 [2] f2 49 [2] d9 65 [2] f7 47 [2] e3 5c [2] ec 46 [2] f2 5b [2] f0 5a [2] eb 5c [2] f7 5b [2] eb 74 }

  condition:
    any of them
}