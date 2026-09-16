rule TTP_XOR_QUAD_CurrentVersionRun_ae74 {
  strings:
    $key_ae74 = { fd 1b [2] d9 15 [2] f2 39 [2] dc 1b [2] c8 00 [2] c7 1a [2] d9 07 [2] db 06 [2] c0 00 [2] dc 07 [2] c0 28 }

  condition:
    any of them
}