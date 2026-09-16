rule TTP_XOR_QUAD_CurrentVersionRun_61cc {
  strings:
    $key_61cc = { 32 a3 [2] 16 ad [2] 3d 81 [2] 13 a3 [2] 07 b8 [2] 08 a2 [2] 16 bf [2] 14 be [2] 0f b8 [2] 13 bf [2] 0f 90 }

  condition:
    any of them
}