rule TTP_XOR_QUAD_CurrentVersionRun_9ecc {
  strings:
    $key_9ecc = { cd a3 [2] e9 ad [2] c2 81 [2] ec a3 [2] f8 b8 [2] f7 a2 [2] e9 bf [2] eb be [2] f0 b8 [2] ec bf [2] f0 90 }

  condition:
    any of them
}